/*
 * Copyright 2017 Dell Inc. or its subsidiaries.  All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <utf.h>
#include <bson.h>
#include <json.h>

/*
 * Escape or unescape a character; returns 0 if no escape is necessary.
 */
static char
json_escape(char c, char q, int esc)
{
	if (c == q)
		return (c);

	if (c == '/' && !esc)
		return (c);

	for (const char *e = "\"\"\\\\\bb\ff\nn\rr\tt"; *e != 0; e += 2)
		if (e[!esc] == c)
			return (e[esc]);

	return (0);
}

static const char *
json_u4x_to_unicode(const char *j, uint32_t *u)
{
	uint32_t u1 = 0;

	if (j[0] != '\\' || j[1] != 'u')
		return (NULL);

	for (int d = 2; d < 6; d++) {
		int8_t c = j[d];
		switch (c) {
		case '0' ... '9':
			c = c - '0';
			break;
		case 'A' ... 'F':
			c = c - 'A' + 10;
			break;
		case 'a' ... 'f':
			c = c - 'a' + 10;
			break;
		default:
			return (NULL);
		}
		u1 = (u1 << 4) | c;
	}
	*u = u1;

	return (j + 6);
}

static const char *
json_string_to_unicode(const char *j, char q, uint32_t *u)
{
	const char *j2;
	uint32_t u2 = 0;

	if ((uint8_t)j[0] < ' ')
		return (NULL);

	if (j[0] != '\\')
		return (unicode_from_utf8(u, j));

	if (j[1] != 'u') {
		char e = json_escape(j[1], q, 0);
		if (e != 0) {
			*u = (uint8_t)e;
			return (j + 2);
		}
		return (NULL);
	}

	if ((j = json_u4x_to_unicode(j, u)) != NULL && unicode_is_sp1(*u) &&
	    (j2 = json_u4x_to_unicode(j, &u2)) != NULL && unicode_is_sp2(u2)) {
		*u = unicode_from_sp(*u, u2);
		j = j2;
	}

	return (j);
}

static char *
json_string_from_unicode(char *j, char q, uint32_t u)
{
	if (u < 0x80) {
		char e = json_escape((char)u, q, 1);
		if (e != 0) {
			j[0] = '\\';
			j[1] = e;
			return (j + 2);
		}
		if (u < ' ') {
			return (j + snprintf(j, 7, "\\u%04X", u));
		}
	}

	return (unicode_to_utf8(u, j));
}

/*
 * Convert the JSON string j to the UTF-8 string s.
 *
 * If s == NULL, returns the size of the buffer (including null terminator)
 * that would be required to hold the UTF-8 string.
 *
 * If s != NULL, generates e and returns number of characters of 'j' consumed.
 *
 * Returns 0 if 'j' is not a valid JSON string.
 */
int32_t
json_string_to_utf8(const char *j, char q, char *s, int m)
{
	const char *j0 = j;
	char *s0 = s;
	int32_t size = 1;

	if (*j++ != q)
		return (0);

	while (*j != q) {
		char buf[4], *b;
		uint32_t u;

		j = json_string_to_unicode(j, q, &u);
		b = s0 ? s : buf;
		s = u ? unicode_to_utf8(u, b) : unicode_to_utf8_n(u, b, 1 + m);

		if (j == NULL || s == NULL)
			return (0);

		size += s - b;
	}

	if (s0) {
		*s = '\0';
		size = ++j - j0;
	}

	return (size);
}

int32_t
json_string_from_utf8(char *j, char q, const char *s, int len)
{
	char *j0 = j++;
	int32_t size = 2;

	while (len > 1) {
		const char *s0 = s;
		char buf[7], *b;
		uint32_t u;

		s = unicode_from_utf8(&u, s0);
		b = j0 ? j : buf;
		j = json_string_from_unicode(b, q, u);

		if (s == NULL || j == NULL)
			return (0);

		size += j - b;
		len -= (s - s0);
	}

	if (len != 1 || s[0] != 0)
		return (0);

	if (j0) {
		*j0 = q;
		*j = q;
		*++j = '\0';
	}

	return (size);
}

/*
 * Ingest the expected string 'm' and any subsequent whitespace,
 * including C/C++ comments.
 */
static int
json_ingest(bson_t *b, const char **j, const char *m)
{
	int c_comment = 0;
	int cpp_comment = 0;

	for (; *m != '\0' && *m == **j; m++, (*j)++)
		continue;

	if (*m != '\0')
		return (EINVAL);

	for (; **j != '\0'; (*j)++) {
		switch (**j) {

		case '\n':
			b->b_parse_line++;
			cpp_comment = 0;
			break;

		case '\r':
		case '\t':
		case ' ':
			break;

		case '/':
			if (c_comment) {
				if (j[0][-1] == '*')
					c_comment = 0;
				break;
			}

			if (cpp_comment)
				break;

			if (j[0][1] == '*') {
				c_comment = 1;
				break;
			}

			if (j[0][1] == '/') {
				cpp_comment = 1;
				break;
			}

			return (0);

		default:
			if (!c_comment && !cpp_comment)
				return (0);
			break;
		}
	}

	return (0);
}

/*
 * Convert a JSON string to UTF-8(m) in a temporary buffer after the
 * end of the BSON document, so that no memory allocation is required.
 * There must be enough space for both the string and the expanded document
 * that will contain it, so that bson_gap() doesn't overwrite the string.
 * xsize is the amount the document will expand in addition to the string;
 * it is either 1 byte for a BSON type, or 4 bytes for a BSON_STRING size.
 * The memory layout looks like this:
 *
 *	|docsize| xsize	| *size	| *size	|remaining space|
 *	^			^	^		^
 *	doc			*s	*s + *size	doc + b->b_bufsize
 *
 * Alternatively, if memory allocation is available (b->b_vmem != NULL),
 * just use that.
 */
static int
json_strbuf(const bson_t *b, const char **j, char q, char **s, int32_t *size,
    int32_t xsize, int m)
{
	char *doc = b->b_buf;
	int32_t docsize = b->b_docsize;

	*s = NULL;
	*size = json_string_to_utf8(*j, q, NULL, m);

	if (*size == 0)
		return (EINVAL);

	if (b->b_vmem != NULL) {
		*s = vmem_alloc(b->b_vmem, (size_t)*size, VM_SLEEP);
	} else {
		*s = doc + docsize + xsize + *size;
		if (*s + *size > doc + b->b_bufsize)
			return (ENOMEM);
	}

	*j += json_string_to_utf8(*j, q, *s, m);

	return (0);
}

static void
json_strfree(const bson_t *b, char *s, int32_t size)
{
	if (b->b_vmem != NULL && s != NULL)
		vmem_free(b->b_vmem, s, (size_t)size);
}

static bson_type_t
bson_type_match(const char *str, size_t len)
{
	int pos;
	for (pos = 0; pos < BSON_TYPES; pos++)
		if ((strncmp(str, bson_type_name[pos], len) == 0) &&
		    (bson_type_name[pos][len] == '\0'))
			return (pos);
	return (BSON_MAX_KEY);
}

int
json_parse(bson_t *b, const char **j, char q, off_t v, int a,
    json_parse_cb *cb, void *arg)
{
	char numbuf[16];
	char *n, *s, *ed, *ei;
	int32_t size;
	int64_t i64;
	int8_t type = BSON_UNDEFINED;
	double d;
        const char *m;
	int line;
	int err;

	if ((err = json_ingest(b, j, "")) != 0)
		return (err);

	line = b->b_parse_line;

	if (**j == '(') {
		const char *end;

		if ((err = json_ingest(b, j, "(")))
			return (err);
		if ((end = strchr(*j, ')')) == NULL)
			return (EINVAL);
		type = bson_type_match(*j, end - *j);
		if (type == BSON_MAX_KEY)
			return (EINVAL);
		*j = end;
		if ((err = json_ingest(b, j, ")")) ||
		    (err = json_ingest(b, j, ""))) {
			return (err);
		}
	}
	if (v >= 0) {
		if (a == -1) {
			if ((err = json_strbuf(b, j, q, &n, &size, 1, 1)) ||
			    (err = json_ingest(b, j, "")) ||
			    (err = json_ingest(b, j, ":")) ||
			    (err = json_ingest(b, j, ""))) {
				json_strfree(b, n, size);
				return (err);
			}
			if (b->b_sep != 0 && strchr(n, b->b_sep) != NULL) {
				err = EINVAL;
			} else {
				err = bson_add(b, v, n, NULL, BSON_UNDEFINED);
			}
			json_strfree(b, n, size);
		} else {
			(void) snprintf(numbuf, sizeof (numbuf), "%d", a);
			err = bson_add(b, v, numbuf, NULL, BSON_UNDEFINED);
		}
	}

	if (err)
		return (err);

	v = b->b_value[b->b_depth];

	switch (**j) {

	case '{':
		if ((err = bson_set_object(b, v, NULL, NULL, bson_empty)) != 0)
			return (err);

		if (cb != NULL) {
			cb(b, line, arg);
			line = -1; // indicates end of document
		}

		if ((err = json_ingest(b, j, "{")) != 0)
			return (err);

		for (a = 0; **j != '}'; a++) {
			if (a != 0 && (err = json_ingest(b, j, ",")) != 0)
				return (err);
			if ((err = json_parse(b, j, q, v, -1, cb, arg)) != 0)
				return (err);
		}
		m = "}";
                break;

	case '[':
		if ((err = bson_set_array(b, v, NULL, NULL, bson_empty)) != 0)
			return (err);

		if (cb != NULL) {
			cb(b, line, arg);
			line = -1;
		}

		if ((err = json_ingest(b, j, "[")) != 0)
			return (err);

		for (a = 0; **j != ']'; a++) {
			if (a != 0 && (err = json_ingest(b, j, ",")) != 0)
				return (err);
			if ((err = json_parse(b, j, q, v, a, cb, arg)) != 0)
				return (err);
		}
		m = "]";
                break;

	case '"':
	case '\'':
		err = json_strbuf(b, j, q, &s, &size, sizeof (size), 0);

		if (err == 0)
			err = bson_set(b, v, NULL, NULL, BSON_STRING, &size, s);

		json_strfree(b, s, size);

		if (err)
			return (err);

		m = "";
                break;

	case '-':
	case '0' ... '9':
		errno = 0;
		d = strtod(*j, &ed);
		if (errno != 0 || ed == *j)
			return (EINVAL);
		i64 = strtoll(*j, &ei, 0);
		*j = ed;

		if (errno == 0 && ed == ei) {
			if ((type == BSON_INT32) &&
			    (i64 >= INT32_MIN) &&
			    (i64 <= INT32_MAX)) {
				err = bson_set_int32(b, v, NULL, (int32_t) i64);
			} else {
				err = bson_set_int64(b, v, NULL, i64);
			}
		} else {
			err = bson_set_double(b, v, NULL, d);
		}

		if (err)
			return (err);

		m = "";
                break;

	case 't':
		if ((err = bson_set_boolean(b, v, NULL, 1)))
			return (err);
		m = json_true;
                break;

	case 'f':
		if ((err = bson_set_boolean(b, v, NULL, 0)))
			return (err);
		m = json_false;
                break;

	case 'n':
		if ((err = bson_set(b, v, NULL, NULL, BSON_NULL)))
			return (err);
		m = json_null;
                break;

	default:
		return (EINVAL);
	}

	if (cb != NULL)
		cb(b, line, arg);

	return (json_ingest(b, j, m));
}
