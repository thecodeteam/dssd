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

#ifndef	_BSON_H
#define	_BSON_H

#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdarg.h>
#include <errno.h>
#ifdef BSON_ALTERNATE_BUILD
#include <sys/types.h>
#include <vmem_stubs.h>
#else
#include <stdio.h>
#include <vmem.h>
#endif

#ifdef	__cplusplus
extern "C" {
#endif

typedef enum bson_type {
	BSON_ZERO	= 0x00,
	BSON_DOUBLE	= 0x01,
	BSON_STRING	= 0x02,
	BSON_OBJECT	= 0x03,
	BSON_ARRAY	= 0x04,
	BSON_BINARY	= 0x05,
	BSON_UNDEFINED	= 0x06,
	BSON_OID	= 0x07,
	BSON_BOOLEAN	= 0x08,
	BSON_UTC	= 0x09,
	BSON_NULL	= 0x0A,
	BSON_REGEX	= 0x0B,
	BSON_DBREF	= 0x0C,
	BSON_CODE	= 0x0D,
	BSON_SYMBOL	= 0x0E,
	BSON_CODEWS	= 0x0F,
	BSON_INT32	= 0x10,
	BSON_TIMESTAMP	= 0x11,
	BSON_INT64	= 0x12,
	BSON_TYPES	= 0x13,		// current limit
	BSON_TYPE_NAME	= BSON_TYPES,	// pseudo-type for element type + name
	BSON_BUFFER	= BSON_TYPES + 1, // pseudo-type for bson_set_buffer()
	BSON_STRBUF	= BSON_TYPES + 2, // pseudo-type for bson_add_sprintf()
	BSON_MIN_KEY	= 0xFF,
	BSON_MAX_KEY	= 0x7F,
} bson_type_t;

typedef enum bson_binary_subtype {
	BSON_BIN_BINARY	= 0x00,
	BSON_BIN_FUNC	= 0x01,
	BSON_BIN_OLD	= 0x02,
	BSON_BIN_UUID	= 0x03,
	BSON_BIN_MD5	= 0x05,
	BSON_BIN_USER	= 0x80,
} bson_binary_subtype_t;

typedef enum json_scope {
	JSON_PURE	= 1,	// allow only BSON types that map 1-1 to JSON
	JSON_PRINTABLE	= 2,	// allow any BSON type that is printable
	JSON_TYPED	= 3,	// allow all BSON types, output as typed JSON
	JSON_BSON	= 4,	// allow all BSON types, output as BSON
} json_scope_t;

typedef enum json_format {
	JSON_PRETTY	= 1,	// elements newline-delimited, tab-indented
	JSON_COMPACT	= 2,	// no extra whitespace
} json_format_t;

extern const char * const bson_type_name[BSON_TYPES];
extern const char bson_empty[5];

extern const char json_true[5];
extern const char json_false[6];
extern const char json_null[5];

#define	BSON_MAX_DEPTH		32

typedef struct bson bson_t;
typedef void bson_err_f(bson_t *, off_t, const char *, int8_t, int,
    const char *);

struct bson {
	char *b_buf;		// buffer containing bson document
	size_t b_bufsize;	// size of buffer (document may be smaller)
	vmem_t *b_vmem;		// vmem arena (NULL if using fixed-size buffer)
	char b_sep;		// name separator (usually '.')
	char b_quote;		// string quote (usually '"')
	int8_t b_rdonly: 1;	// non-zero if buffer is read-only
	int8_t b_szlock: 1;	// non-zero if buffer size is not modifiable
	int8_t b_doctype;	// document type
	int32_t b_docsize;	// document size
	bson_err_f *b_errfunc;	// error callback
	char b_parse_err[40];	// context of last parse error
	int b_parse_line;	// line number of last parse error
	int b_depth;		// depth of object lookup stack
	int32_t b_value[BSON_MAX_DEPTH]; // value offset (into b_buf)
	int32_t b_type[BSON_MAX_DEPTH]; // type offset (into b_buf)
};

typedef int (*bson_err_printf_func)(const char *, ...);

extern bson_err_printf_func bson_err_printf
    __attribute__ ((format(printf, 1, 2)));

#ifndef BSON_ALTERNATE_BUILD
extern bson_err_f bson_fatal;
#endif
extern bson_err_f bson_warn;

extern off_t bson_first(bson_t *b, off_t d);
extern off_t bson_next(bson_t *b, off_t e,
    int8_t *tp, const char **np, off_t *vp);
extern int32_t bson_get_size(const char *v);

extern void bson_init(bson_t *b, char *buf, size_t size, vmem_t *vm,
    char sep, int8_t t, bson_err_f *);
extern void bson_set_readonly(bson_t *b);
extern void bson_set_sizelock(bson_t *b, int);
extern void bson_fini(bson_t *b);
extern int bson_resize(bson_t *, size_t);

extern int bson_exists(bson_t *b, off_t d, const char *p, off_t *o, int8_t *t);
extern int bson_lookup(bson_t *b, off_t d, const char *p, off_t *o, int8_t *t);
extern int bson_get(bson_t *b, off_t d, const char *p, off_t *o, int8_t t, ...);
extern int bson_set(bson_t *b, off_t d, const char *p, off_t *o, int8_t t, ...);
extern int bson_add(bson_t *b, off_t d, const char *p, off_t *o, int8_t t, ...);
extern int bson_remove(bson_t *b, off_t d, const char *p);
#ifndef BSON_ALTERNATE_BUILD
extern int bson_concat(bson_t *b, off_t d, const char *p, int8_t t, ...);
#endif
extern int bson_set_buffer(bson_t *b, off_t d, const char *p, off_t *o,
    int32_t size);
extern int bson_add_sprintf(bson_t *b, off_t d, const char *p,
    const char *fmt, ...) __attribute__((format(__printf__, 4, 5)));
extern int bson_add_vsprintf(bson_t *b, off_t d, const char *p,
    const char *fmt, va_list ap) __attribute__((format(__printf__, 4, 0)));
extern int bson_get_encoded_value_size(bson_t *b, off_t d, size_t *sizep);
extern int bson_verify(bson_t *b, off_t d, const char *p, json_scope_t js);
extern int bson_to_json(bson_t *b, off_t d, const char *p, json_scope_t js,
    json_format_t jf, char *j, size_t bufsize, size_t *jsize);

/*
 * The parse callback provides line number information for each parsed element.
 * The "line" argument is the line number of the name; the line number of the
 * value (in case it differs) can be obtained from b->b_parse_line. All
 * component names, types, and values from the outermost document to the
 * just-parsed element can be obtained from the bson stack. A special callback
 * with a "line" argument of -1 indicates the end of an object or array.
 */
typedef void json_parse_cb(bson_t *b, int line, void *arg);

extern int bson_from_json(bson_t *b, off_t d, const char *p, json_scope_t js,
    const char *j, json_parse_cb *cb, void *arg);

#ifndef BSON_ALTERNATE_BUILD
extern int bson_read_fd(bson_t *b, off_t d, const char *p, json_scope_t js,
    int fd, json_parse_cb *cb, void *arg);
extern int bson_read_stream(bson_t *b, off_t d, const char *p, json_scope_t js,
    FILE *fp, json_parse_cb *cb, void *arg);
extern int bson_read_file(bson_t *b, off_t d, const char *p, json_scope_t js,
    const char *path, json_parse_cb *cb, void *arg);
extern int bson_read_buf(bson_t *b, off_t d, const char *p, json_scope_t js,
    const char *j, json_parse_cb *cb, void *arg);

extern int bson_write_fd(bson_t *b, off_t d, const char *p, json_scope_t js,
    json_format_t jf, int fd);
extern int bson_write_stream(bson_t *b, off_t d, const char *p, json_scope_t js,
    json_format_t jf, FILE *fp);
extern int bson_write_file(bson_t *b, off_t d, const char *p, json_scope_t js,
    json_format_t jf, const char *path);
extern int bson_write_buf(bson_t *b, off_t d, const char *p, json_scope_t js,
    json_format_t jf, char *j, size_t bufsize, size_t *jsize);

extern int bson_write_alloc(bson_t *b, off_t d, const char *p, json_scope_t js,
    json_format_t jf, char **j, size_t *jsize);
extern void bson_write_free(bson_t *b, char *j, size_t jsize);
#endif

/*
 * Strongly typed wrapper functions for common operations on common types:
 * bson_{get,set,add}_{object,array,string,double,boolean,int32,int64}().
 */
static inline int
bson_get_object(bson_t *b, off_t d, const char *p, off_t *o, const char **v)
{
	return (bson_get(b, d, p, o, BSON_OBJECT, v));
}

static inline int
bson_set_object(bson_t *b, off_t d, const char *p, off_t *o, const char *v)
{
	return (bson_set(b, d, p, o, BSON_OBJECT, v));
}

static inline int
bson_add_object(bson_t *b, off_t d, const char *p, off_t *o, const char *v)
{
	return (bson_add(b, d, p, o, BSON_OBJECT, v));
}

static inline int
bson_get_array(bson_t *b, off_t d, const char *p, off_t *o, const char **v)
{
	return (bson_get(b, d, p, o, BSON_ARRAY, v));
}

static inline int
bson_set_array(bson_t *b, off_t d, const char *p, off_t *o, const char *v)
{
	return (bson_set(b, d, p, o, BSON_ARRAY, v));
}

static inline int
bson_add_array(bson_t *b, off_t d, const char *p, off_t *o, const char *v)
{
	return (bson_add(b, d, p, o, BSON_ARRAY, v));
}

static inline int
bson_get_string(bson_t *b, off_t d, const char *p, const char **v)
{
	int32_t size;
	return (bson_get(b, d, p, NULL, BSON_STRING, &size, v));
}

static inline int
bson_set_string(bson_t *b, off_t d, const char *p, const char *v)
{
	int32_t size = strlen(v) + 1;
	return (bson_set(b, d, p, NULL, BSON_STRING, &size, v));
}

static inline int
bson_add_string(bson_t *b, off_t d, const char *p, const char *v)
{
	int32_t size = strlen(v) + 1;
	return (bson_add(b, d, p, NULL, BSON_STRING, &size, v));
}

#ifndef BSON_ALTERNATE_BUILD
static inline int
bson_concat_string(bson_t *b, off_t d, const char *p, const char *v)
{
	int32_t size = strlen(v) + 1;
	return (bson_concat(b, d, p, BSON_STRING, &size, v));
}
#endif

static inline int
bson_get_double(bson_t *b, off_t d, const char *p, double *v)
{
	return (bson_get(b, d, p, NULL, BSON_DOUBLE, v));
}

static inline int
bson_set_double(bson_t *b, off_t d, const char *p, double v)
{
	return (bson_set(b, d, p, NULL, BSON_DOUBLE, &v));
}

static inline int
bson_add_double(bson_t *b, off_t d, const char *p, double v)
{
	return (bson_add(b, d, p, NULL, BSON_DOUBLE, &v));
}

static inline int
bson_get_boolean(bson_t *b, off_t d, const char *p, int8_t *v)
{
	return (bson_get(b, d, p, NULL, BSON_BOOLEAN, v));
}

static inline int
bson_set_boolean(bson_t *b, off_t d, const char *p, int8_t v)
{
	return (bson_set(b, d, p, NULL, BSON_BOOLEAN, &v));
}

static inline int
bson_add_boolean(bson_t *b, off_t d, const char *p, int8_t v)
{
	return (bson_add(b, d, p, NULL, BSON_BOOLEAN, &v));
}

static inline int
bson_get_int32(bson_t *b, off_t d, const char *p, int32_t *v)
{
	return (bson_get(b, d, p, NULL, BSON_INT32, v));
}

static inline int
bson_set_int32(bson_t *b, off_t d, const char *p, int32_t v)
{
	return (bson_set(b, d, p, NULL, BSON_INT32, &v));
}

static inline int
bson_add_int32(bson_t *b, off_t d, const char *p, int32_t v)
{
	return (bson_add(b, d, p, NULL, BSON_INT32, &v));
}

static inline int
bson_get_int64(bson_t *b, off_t d, const char *p, int64_t *v)
{
	return (bson_get(b, d, p, NULL, BSON_INT64, v));
}

static inline int
bson_set_int64(bson_t *b, off_t d, const char *p, int64_t v)
{
	return (bson_set(b, d, p, NULL, BSON_INT64, &v));
}

static inline int
bson_add_int64(bson_t *b, off_t d, const char *p, int64_t v)
{
	return (bson_add(b, d, p, NULL, BSON_INT64, &v));
}

static inline int
bson_get_binary(bson_t *b, off_t d, const char *p, int32_t *size, void **data)
{
	int8_t subtype;
	return (bson_get(b, d, p, NULL, BSON_BINARY, size, &subtype, data));
}

static inline int
bson_set_binary(bson_t *b, off_t d, const char *p, int32_t size,
    const void *data)
{
	int8_t subtype = BSON_BIN_BINARY;
	return (bson_set(b, d, p, NULL, BSON_BINARY, &size, &subtype, data));
}

static inline int
bson_add_binary(bson_t *b, off_t d, const char *p, int32_t size,
    const void *data)
{
	int8_t subtype = BSON_BIN_BINARY;
	return (bson_add(b, d, p, NULL, BSON_BINARY, &size, &subtype, data));
}

#ifndef BSON_ALTERNATE_BUILD
static inline int
bson_concat_binary(bson_t *b, off_t d, const char *p, int32_t size,
    const void *data)
{
	return (bson_concat(b, d, p, BSON_BINARY, &size, data));
}
#endif

/*
 * Routines that return the value directly, with no error reporting.
 * These should only be used when bson_init() has been called with a
 * suitable error handler.  The argument against such routines is that
 * they encourage sloppy programming.  My counterargument is that
 * if routines like this aren't provided, you'll write them yourself.
 */
static inline off_t
bson_getv(bson_t *b, off_t d, const char *p, int8_t type)
{
	int8_t t;
	off_t v;
	return (bson_lookup(b, d, p, &v, &t) || t != type ? -1 : v);
}

static inline const char *
bson_getv_object(bson_t *b, off_t d, const char *p)
{
	const char *v;
	return (bson_get(b, d, p, NULL, BSON_OBJECT, &v) ? NULL : v);
}

static inline const char *
bson_getv_array(bson_t *b, off_t d, const char *p)
{
	const char *v;
	return (bson_get(b, d, p, NULL, BSON_ARRAY, &v) ? NULL : v);
}

static inline const char *
bson_getv_string(bson_t *b, off_t d, const char *p)
{
	int32_t size;
	const char *v;
	return (bson_get(b, d, p, NULL, BSON_STRING, &size, &v) ? NULL : v);
}

static inline double
bson_getv_double(bson_t *b, off_t d, const char *p)
{
	double v;
	return (bson_get(b, d, p, NULL, BSON_DOUBLE, &v) ? 0.0 : v);
}

static inline int8_t
bson_getv_boolean(bson_t *b, off_t d, const char *p)
{
	int8_t v;
	return (bson_get(b, d, p, NULL, BSON_BOOLEAN, &v) ? -1 : v);
}

static inline int32_t
bson_getv_int32(bson_t *b, off_t d, const char *p)
{
	int32_t v;
	return (bson_get(b, d, p, NULL, BSON_INT32, &v) ? -1 : v);
}

static inline int64_t
bson_getv_int64(bson_t *b, off_t d, const char *p)
{
	int64_t v;
	return (bson_get(b, d, p, NULL, BSON_INT64, &v) ? -1 : v);
}

#ifdef	__cplusplus
}
#endif

#endif	/* _BSON_H */
