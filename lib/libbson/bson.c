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
#include <inttypes.h>
#ifndef BSON_ALTERNATE_BUILD
#include <assert.h>
#else
#define assert(expr) /* do nothing */
#endif

/**
 * @fi bson.c
 * @br BSON / JSON Document Processor @bc
 *
 * 1. Introduction
 * ---------------
 *
 * BSON and JSON are generic self-describing document formats, akin to XML.
 * This library provides routines to create and edit BSON and JSON documents,
 * and to convert between the BSON and JSON formats.
 *
 *
 * 1.1. JSON
 * ---------
 *
 * JSON (JavaScript Object Notation) is a general-purpose grammar for
 * describing structured documents.  An overview is available here:
 *
 *	http://www.json.org
 *
 * The complete specification is in this RFC:
 *
 *	http://www.ietf.org/rfc/rfc4627.txt
 *
 * Briefly, a JSON document is a list of name/value pairs, where each name is
 * a string and each value is either another JSON object, a number, a string,
 * or one of three literal values:  true, false, null.  JSON also supports
 * arrays, a variant of object bracketed by [] rather than {}, in which the
 * names are implicit:  they are the array indexes "0", "1", "2", etc.
 *
 * The following JSON document illustrates all JSON types.  It contains an
 * array "a" and an object "o".  a[0] is an object containing "pi" and "year",
 * a[1]=true, a[2]=false, a[3]=null, and o has "up"="above" and "down"="below".
 *
 *	{
 *		"a": [
 *			{
 *				"pi": 3.14,
 *				"year": 2012
 *			},
 *			true,
 *			false,
 *			null
 *		],
 *		"o": {
 *			"up": "above",
 *			"down": "below"
 *		}
 *	}
 *
 *
 * 1.2. BSON
 * ---------
 *
 * BSON (Binary JSON) is a superset of JSON that provides strong typing,
 * additional types, and a binary structure that can be parsed quickly.
 * An overview is available here:
 *
 *	http://bsonspec.org
 *
 * The BSON form of the JSON example above consists of the following binary:
 *
 *	60  00  00  00  04  61  00  32  00  00  00  03  30  00  1f  00
 *	00  00  01  70  69  00  1f  85  eb  51  b8  1e  09  40  12  79
 *	65  61  72  00  dc  07  00  00  00  00  00  00  00  08  31  00
 *	01  08  32  00  00  0a  33  00  00  03  6f  00  23  00  00  00
 *	02  75  70  00  06  00  00  00  61  62  6f  76  65  00  02  64
 *	6f  77  6e  00  06  00  00  00  62  65  6c  6f  77  00  00  00
 *
 * Matching this up with the JSON above, we have:
 *
 *	60 00 00 00 (document size, little-endian) {
 *		04 (array) 61 00 = "a": 32 00 00 00 (array size) [
 *			03 (object) 30 00 = "0": 1f 00 00 00 (object size) {
 *				01 (double) 70 69 00 = "pi":
 *				    1f 85 eb 51 b8 1e 09 40 = 3.14,
 *				12 (int64) 79 65 61 72 0 = "year":
 *				    dc 07 00 00 00 00 00 00 = 2012
 *			} 00 (end-of-object),
 *			08 (boolean) 31 00 = "1": 01 = true,
 *			08 (boolean) 32 00 = "2": 00 = false,
 *			0a (null) 33 00 = "3":
 *		] 00 (end-of-array)
 *		03 (object) 6f 00 = "o": 23 00 00 00 (object size) {
 *			02 (string) 75 70 0 = "up":
 *			    06 00 00 00 (strsize) 61 62 6f 76 65 00 = "above",
 *			02 (string) 65 6f 77 63 0 = "down":
 *			    06 00 00 00 (strsize) 62 65 6c 6f 77 00 = "below"
 *		} 00 (end-of-object)
 *	} 00 (end-of-document)
 *
 *
 * 1.3. BSON/JSON relationship
 * ---------------------------
 *
 * Any JSON document can be represented in BSON because BSON is a superset.
 * However, JSON numbers are untyped, whereas BSON numbers are explicitly
 * int32, int64, or double.  Lossless conversion between BSON and JSON
 * requires two conventions: (1) floating-point numbers provided as JSON
 * input must contain either a decimal point or an e/E (as in 5.2e+17);
 * (2) all integers in a BSON document must be type int64.  If these two
 * conventions are followed, a document can be converted between JSON and
 * BSON formats without any loss of precision or change of BSON type.
 *
 *
 * 1.4. Naming conventions
 * -----------------------
 *
 * Although BSON/JSON strings may contain any characters, it is customary
 * to reserve '.' as a separator so that nested objects can be referenced
 * like they would be in JavaScript: in our example, "o.up" = "above".
 * Array elements are named by index: "a.0.pi" = 3.14, "a.1" = true, etc.
 *
 *
 * 2. BSON / JSON Document Processor
 * ---------------------------------
 *
 * This library operates on documents in BSON format, because that format
 * is easier to manipulate than JSON, strongly typed, and larger in scope.
 *
 *
 * 2.1. Initialization
 * -------------------
 *
 * Processing begins with bson_init(&b, buf, size, vm, sep, type, errfunc):
 *
 *	b is an opaque bson_t handle
 *
 *	buf and size are a caller-supplied buffer, with vm == NULL; or,
 *	buf == NULL, size == 0, and vm is a vmem arena to allocate space
 *
 *	sep is the name separator (typically '.')
 *
 *	type is the buffer's initial content type (BSON_NULL if none)
 *
 *	errfunc is an optional function to call when a BSON error occurs.
 *
 * If the buffer already contains a bson document (e.g. if it was read from
 * disk, over a network, or is in ROM), specify its type as BSON_OBJECT.
 *
 * If the initial content is a JSON document, use bson_from_json() (see below)
 * or read from file/stream/etc using bson_read_{fd,stream,file,buf}().
 *
 * Note that when the initial content is BSON_NULL, this is a BSON *value* of
 * size zero, *not* an empty BSON document.  To create an empty document, use
 *
 *	bson_set(b, 0, NULL, NULL, BSON_OBJECT, bson_empty);
 * or
 *	bson_set_object(b, 0, NULL, NULL, bson_empty);
 *
 * This is only necessary when building a document "by hand", i.e. using a
 * series of bson_add() calls rather than bson_read_{fd,stream,file,buf}().
 *
 *
 * 2.2. Processing
 * ---------------
 *
 * A BSON document is a tree, so its elements can be named by a 'directory'
 * and a relative 'pathname'.  Using the example document above, the following
 * directory/pathname combinations are equivalent ways to name "o.up":
 *
 *	d = 0 (root)	p = "o.up"
 *	d = o		p = "up"
 *	d = o.up	p = NULL (leaf)
 *
 * There are routines to get, set, add, remove, lookup, and verify content;
 * they all use this directory/pathname convention.  A few examples:
 *
 *	off_t a0;		// directory index for object a[0] aka a.0
 *	double pi;
 *	int8_t t;
 *	int64_t year;
 *	int32_t answer = 42;
 *
 *	bson_get_object(b, 0, "a.0", &a0);		// get a0 = a.0
 *	bson_get_double(b, a0, "pi", &pi);		// get pi = 3.14
 *	bson_get_int64(b, a0, "year", &year);		// get year = 2012
 *	year++;						// year = 2013
 *	bson_set_int64(b, a0, "year", year);		// set year = 2013
 *	bson_add_int32(b, a0, "answer", answer);	// add a.0.answer = 42
 *	bson_add_string(b, a0, "foo", "bar");		// add a.0.foo = "bar"
 *
 * There are similar functions for all common operations on common types:
 * bson_{get,set,add}_{object,array,boolean,int32,int64,double,string}().
 *
 * In addition, there are universal bson_{get,set,add}() varargs routines
 * that can handle any BSON type.  Using these, the above code sample becomes:
 *
 *	bson_get(b, 0, "a.0", op, BSON_OBJECT, &a0);	// get a0 = a.0
 *	bson_get(b, a0, "pi", op, BSON_DOUBLE, &pi);	// get pi = 3.14
 *	bson_get(b, a0, "year", op, BSON_INT64, &year); // get year = 2012
 *	year++;						// year = 2013
 *	bson_set(b, a0, "year", op, BSON_INT64, &year);	// set year = 2013
 *	bson_add(b, a0, "answer", op, BSON_INT32, &answer); // add a.0.answer=42
 *
 * The op (offset pointer) argument, if non-NULL, will be filled with the
 * value's offset into the document.  This is the same offset as bson_lookup().
 *
 * Adding "foo" takes a bit more work because the underlying BSON_STRING type
 * is actually allowed to contain null bytes, so the size must be specified:
 *
 *	char *s = "bar";				// s = string to add
 *	int32_t size = strlen(bar) + 1;			// size, including \0
 *	bson_add(b, a0, "foo", op, BSON_STRING, &size, s); // add a.0.foo="bar"
 *
 * Either way, after these operations the document content would be as follows:
 *
 *	{
 *		"a": [
 *			{
 *				"pi": 3.14,
 *				"year": 2013,		// initially 2012
 *				"answer": 42,		// added this element
 *				"foo": "bar"		// added this element
 *			},
 *			true,
 *			false,
 *			null
 *		],
 *		"o": {
 *			"up": "above",
 *			"down": "below"
 *		}
 *	}
 *
 * Members of an object can also be removed:
 *
 *	bson_remove(b, 0, "a");				// remove a, leaving o
 *
 * This removes the entire array a[], leaving just o:
 *
 *	{
 *		"o": {
 *			"up": "above",
 *			"down": "below"
 *		}
 *	}
 *
 * bson_verify() verifies that a document contains valid content for the
 * specified scope:
 *
 *	bson_verify(b, d, p, JSON_PURE);
 *
 * The 'json_scope_t' argument to bson_verify() indicates whether the document
 * is allowed to contain only pure JSON types (JSON_PURE), or any type that
 * is printable as JSON (JSON_PRINTABLE), or any BSON type at all (JSON_BSON).
 * As usual, since d == 0 implies the root and p == NULL implies no path,
 * bson_verify(b, 0, NULL, JSON_PURE) verifies the entire document.
 *
 * Every function mentioned above is of type int, returning 0 on success
 * and some suitable errno on failure:
 *
 *	EOVERFLOW	document nesting too deep
 *	ENOMEM		buffer too small for requested operation
 *	ENOTDIR		attempted lookup in non-document (object/array) type
 *	ENOTSUP		operation not supported
 *	ENOENT		item not found in document
 *	EPROTOTYPE	item not of requested type
 *	EBUSY		attempt to bson_remove() root
 *	EINVAL		invalid value (e.g. string not valid UTF-8)
 *	ERANGE		array index invalid
 *	E2BIG		excess characters after document end
 *	EBADF		document corrupted
 *	EDOM		BSON type out of scope
 *	EROFS		document is read only
 *
 *
 * 2.3. Conversion
 * ---------------
 *
 * Documents can be converted between BSON and JSON forms.  In particular,
 * it is common to initialize BSON documents from JSON, since the latter
 * is easily edited as a text file.
 *
 *
 * 2.3.1. Low-level conversion routines
 * -----------------------------------
 *
 * bson_to_json(b, d, p, JSON_PURE, NULL, 0, &size) [first call]
 *
 *	Determine the buffer size necessary to print document as pure JSON.
 *	Sets *size to a non-zero value unless the document is corrupt or
 *	out of scope (e.g. BSON_REGEX elements in a JSON_PURE document).
 *
 * bson_to_json(b, d, p, JSON_PURE, buf, size, &size) [second call]
 *
 *	Print the document into buf.
 *
 * bson_from_json(b, d, p, JSON_PURE, j)
 *
 *	Replace the specified value with JSON content from string j.
 *	If d == 0 and p == NULL, this replaces the entire document.
 *
 * Note that conversions need not be of whole documents: for example,
 * bson_to_json(b, a0, NULL, ...) would just generate the JSON for a.0, and
 * bson_from_json(b, a0, "year", JSON_PURE, "2010") is a perfectly
 * valid (if gratuitously cumbersome) way to set the year to 2010.
 *
 *
 * 2.3.2. High-level conversion routines
 * ------------------------------------
 *
 * BSON / JSON documents are often read from or written to files.
 * To make this common use case easy, the following services are provided:
 *
 *	bson_read_fd(..., int fd);
 *	bson_read_stream(..., FILE *fp);
 *	bson_read_file(..., const char *path);
 *
 *	bson_write_fd(..., int fd);
 *	bson_write_stream(..., FILE *fp);
 *	bson_write_file(..., const char *path);
 *
 *
 * 3. Implementation
 * -----------------
 *
 * A BSON document is a series of fixed-size numbers and variable-size data.
 * Numbers can be 1-byte, 4-byte, or 8-byte signed integers or 8-byte doubles.
 * All other data is preceded by a 4-byte data size (dsize) unless its size
 * is known (e.g. OID is 12 bytes) or easily computed (e.g. by using strlen()).
 *
 * A BSON token can thus be specified by a three-character format string:
 *
 *	type: i|d|p (int, double, or pointer to raw data (string, OID, etc))
 *	size: #|d|s (fixed, specified by prior dsize, or computed by strlen())
 *	kind: n|d|s (numeric, dsize, or string)
 *
 * For example, a 32-bit int has token format "i4n" (int, 4 bytes, numeric).
 * A 64-bit IEEE-754 double has token format "d8n" (double, 8 bytes, numeric).
 * A BSON cstring has token format "pss" (pointer, size strlen() + 1, string).
 *
 * More complex BSON types can be represented by concatenating these tokens.
 * For example, BSON binary data consists of three tokens: a 4-byte dsize,
 * 1-byte subtype, and data.  This is represented by "i4d" + "i1n" + "pdn".
 * The first token sets the dsize, the second sets the subtype, and the third
 * uses the dsize (set by the first token) to determine how much data to copy.
 *
 * Using this representation for BSON tokens, the parser for the BSON grammer
 * can be described by a table of strings that looks exactly like the BSON BNF.
 *
 * The parser itself is a trivial 10-line loop that, for each token, updates
 * a local dsize variable if the kind is 'd', then copies either a fixed-size
 * word or variable-size data depending on the token's type and size.
 *
 *
 * 4. Alternate compilation
 * ------------------------
 *
 * This code can function with or without a memory allocator.  If no memory
 * allocator is available, all services work except the convenience wrappers
 * for file I/O described in section 2.3.2.  These routines are kept in a
 * separate source file, bson_io.c.  To compile without memory allocation,
 * omit bson_io.c and provide stubs for vmem_alloc() and vmem_free() by
 * compiling with -DBSON_ALTERNATE_BUILD.
 *
 * When compiled in this manner, the code has no external dependencies except
 * memmove(), snprintf(), vsnprintf(), strlen(), strtod(), strtol(), and
 * strtoll(). It reduces to a few KB of code that can run in very low-memory
 * environments.
 *
 * The optional error handlers bson_fatal() and bson_warn() are provided for
 * convenience and depend on exit() and vfprintf(). Compiling with
 * -DBSON_ALTERNATE_BUILD removes bson_fatal() and the dependency on exit(). It
 * also removes the dependency on vfprintf() by assigning a stub to
 * bson_err_printf, allowing you to assign your own implementation for use by
 * bson_warn().
 *
 * @ec
 */
typedef struct bson_fmt {
	char f_type;		// i|d|p (int, double, pointer)
	char f_size;		// #|d|s (# - '0' bytes, dsize, strlen() + 1)
	char f_kind;		// n|d|s (numeric, dsize, string)
} __attribute__((packed)) bson_fmt_t;

/*
 * BSON token formats, as described above.
 */
#define	BF_BYTE		"i1n"
#define	BF_INT32	"i4n"
#define	BF_INT64	"i8n"
#define	BF_DOUBLE	"d8n"
#define	BF_DATA_SIZE	"i4d"
#define	BF_ELEMENT_SIZE	"i4n"
#define	BF_OID		"p<n"	// OID is 12 bytes; ASCII '0' + 12 = '<'
#define	BF_BINARY_DATA	"pdn"
#define	BF_STRING_DATA	"pds"
#define	BF_CSTRING	"pss"
#define	BF_DOCUMENT	"pdd"

/*
 * BSON grammar, expressed as concatenation of BSON tokens.
 * The expressions here follow the BSON BNF at bsonspec.org verbatim.
 */
#define	BF_NAME		BF_CSTRING
#define	BF_TYPE		BF_BYTE
#define	BF_SUBTYPE	BF_BYTE
#define	BF_STRING_META	BF_DATA_SIZE
#define	BF_STRING	BF_STRING_META BF_STRING_DATA
#define	BF_BINARY_META	BF_DATA_SIZE BF_SUBTYPE
#define	BF_BINARY	BF_BINARY_META BF_BINARY_DATA
#define	BF_CODEWS	BF_ELEMENT_SIZE BF_STRING BF_DOCUMENT

static const char *bson_format[BSON_TYPES + 3] = {
	[BSON_ZERO]	= NULL,
	[BSON_DOUBLE]	= BF_DOUBLE,
	[BSON_STRING]	= BF_STRING,
	[BSON_OBJECT]	= BF_DOCUMENT,
	[BSON_ARRAY]	= BF_DOCUMENT,
	[BSON_BINARY]	= BF_BINARY,
	[BSON_UNDEFINED] = "",
	[BSON_OID]	= BF_OID,
	[BSON_BOOLEAN]	= BF_BYTE,
	[BSON_UTC]	= BF_INT64,
	[BSON_NULL]	= "",
	[BSON_REGEX]	= BF_CSTRING BF_CSTRING,
	[BSON_DBREF]	= BF_STRING BF_OID,
	[BSON_CODE]	= BF_STRING,
	[BSON_SYMBOL]	= BF_STRING,
	[BSON_CODEWS]	= BF_CODEWS,
	[BSON_INT32]	= BF_INT32,
	[BSON_TIMESTAMP] = BF_INT64,
	[BSON_INT64]	= BF_INT64,
	[BSON_TYPE_NAME] = BF_TYPE BF_NAME,
	[BSON_BUFFER]	= BF_BINARY_META,
	[BSON_STRBUF]	= BF_STRING_META
};

/*
 * JSON grammar is a subset of BSON.  A BSON document can be restricted to
 * allow only JSON types (JSON_PURE), or additional types that are not part
 * of JSON but are printable (JSON_PRINTABLE), or any BSON type (JSON_BSON).
 */
static const uint8_t json_scope[BSON_TYPES] = {
	[BSON_ZERO]	= JSON_BSON,
	[BSON_DOUBLE]	= JSON_PURE,
	[BSON_STRING]	= JSON_PURE,
	[BSON_OBJECT]	= JSON_PURE,
	[BSON_ARRAY]	= JSON_PURE,
	[BSON_BINARY]	= JSON_BSON,
	[BSON_UNDEFINED] = JSON_BSON,
	[BSON_OID]	= JSON_BSON,
	[BSON_BOOLEAN]	= JSON_PURE,
	[BSON_UTC]	= JSON_PRINTABLE,
	[BSON_NULL]	= JSON_PURE,
	[BSON_REGEX]	= JSON_BSON,
	[BSON_DBREF]	= JSON_BSON,
	[BSON_CODE]	= JSON_PRINTABLE,
	[BSON_SYMBOL]	= JSON_PRINTABLE,
	[BSON_CODEWS]	= JSON_BSON,
	[BSON_INT32]	= JSON_PRINTABLE,
	[BSON_TIMESTAMP] = JSON_PRINTABLE,
	[BSON_INT64]	= JSON_PURE,
};

const char * const bson_type_name[BSON_TYPES] = {
	[BSON_ZERO]	= "(none)",
	[BSON_DOUBLE]	= "double",
	[BSON_STRING]	= "string",
	[BSON_OBJECT]	= "object",
	[BSON_ARRAY]	= "array",
	[BSON_BINARY]	= "binary",
	[BSON_UNDEFINED] = "undefined",
	[BSON_OID]	= "OID",
	[BSON_BOOLEAN]	= "boolean",
	[BSON_UTC]	= "UTC",
	[BSON_NULL]	= "null",
	[BSON_REGEX]	= "regex",
	[BSON_DBREF]	= "dbref",
	[BSON_CODE]	= "code",
	[BSON_SYMBOL]	= "symbol",
	[BSON_CODEWS]	= "codews",
	[BSON_INT32]	= "int32",
	[BSON_TIMESTAMP] = "timestamp",
	[BSON_INT64]	= "int64",
};

/*
 * The empty bson document consists of a 4-byte little-endian document size
 * and a trailing zero byte.  It is therefore 5 bytes long, with byte[0] = 5.
 */
const char bson_empty[5] = { 5, 0, 0, 0, 0 };

const char json_true[] = "true";
const char json_false[] = "false";
const char json_null[] = "null";

static int bson_verify_tree(bson_t *, off_t, const char *, off_t, off_t,
    json_scope_t, off_t *);

/*
 * On error, invoke the user's error callback function.
 */
static int
bson_error(bson_t *b, off_t d, const char *p, int8_t t, int err, const char *fn)
{
	if (b->b_errfunc)
		b->b_errfunc(b, d, p, t, err, fn);

	return (err);
}

/*
 * Avoid dependency on strerror() and return messages that are more relevant to
 * libbson.
 */
static const char *
bson_errtext(int err)
{
	switch (err) {
	case EOVERFLOW:
		return ("document nesting too deep");
	case ENOMEM:
		return ("buffer too small for requested operation");
	case ENOTDIR:
		return ("attempted lookup in non-document type");
	case ENOTSUP:
		return ("operation not supported");
	case ENOENT:
		return ("item not found in document");
	case EPROTOTYPE:
		return ("item not of requested type");
	case EBUSY:
		return ("attempt to bson_remove() root");
	case EINVAL:
		return ("invalid value");
	case ERANGE:
		return ("array index or size invalid");
	case E2BIG:
		return ("excess characters after document end");
	case EBADF:
		return ("document corrupted");
	case EDOM:
		return ("BSON type out of scope");
	case EROFS:
		return ("document is read only");
	default:
		return ("unrecognized error");
	}
}

#ifndef BSON_ALTERNATE_BUILD
static int
__attribute__ ((format(printf, 1, 2)))
bson_err_printf_impl(const char *format, ...)
{
	va_list ap;
        int rc;

	va_start(ap, format);
        rc = vfprintf(stderr, format, ap);
	va_end(ap);

	return (rc);
}

bson_err_printf_func bson_err_printf = bson_err_printf_impl;
#else
/* ARGSUSED */
static int
__attribute__ ((format(printf, 1, 2)))
bson_err_printf_dummy(const char *format, ...)
{
	return (0);
}

/*
 * Clients who want the functionality of bson_warn() must supply their own
 * print() function.
 */
bson_err_printf_func bson_err_printf = bson_err_printf_dummy;
#endif

static void
bson_print_err(bson_t *b, off_t d, const char *p, int8_t type, int err,
    const char *f)
{
	(void) bson_err_printf("%s(%p, %d, %s, %s): %s\n",
	    f, b, (int)d, p, bson_type_name[type], bson_errtext(err));

	if (b->b_parse_line != 0)
		(void) bson_err_printf(
                    "syntax error at line %d, context (%s)\n",
		    b->b_parse_line, b->b_parse_err);
}

#ifndef BSON_ALTERNATE_BUILD
void
__attribute__ ((noreturn))
bson_fatal(bson_t *b, off_t d, const char *p, int8_t type, int err,
    const char *f)
{
	bson_print_err(b, d, p, type, err, f);
	exit(1);
}
#endif

void
bson_warn(bson_t *b, off_t d, const char *p, int8_t type, int err,
    const char *f)
{
	bson_print_err(b, d, p, type, err, f);
}

/*
 * Move a word from s to d, converting to/from little-endian along the way.
 */
static void
bson_move_word(char *d, const char *s, int wordsize)
{
	for (int i = 0; i < wordsize; i++)
#if __BYTE_ORDER == __LITTLE_ENDIAN
		d[i] = s[i];
#else
		d[i] = s[wordsize - 1 - i];
#endif
}

/*
 * Get the size of a BSON document, element, string, etc.
 */
int32_t
bson_get_size(const char *v)
{
	int32_t size;

	bson_move_word((void *)&size, v, sizeof (int32_t));

	return (size);
}

/*
 * Set the size of a BSON document, element, string, etc.
 */
static void
bson_set_size(char *v, int32_t size)
{
	bson_move_word(v, (void *)&size, sizeof (int32_t));
}

/*
 * Determine the size of a BSON token given its maximum possible size n.
 * If the token is a dsize record (f->f_kind == 'd'), set *dsize.  The token
 * size then comes from either *dsize ('d'), strlen(v) + 1 ('s'), or taking
 * f->f_size as an ASCII digit. Will not touch memory >= v + n.
 * Return a value greater than n if the token is too large.
 */
static int32_t
bson_token_size(const bson_fmt_t *f, const char *v, size_t n, int32_t *dsize)
{
	if (f->f_kind == 'd') {
		if (n < sizeof (int32_t))
			return (sizeof (int32_t));
		*dsize = bson_get_size(v);
	}

	if (f->f_size == 'd')
		return (*dsize);

	if (f->f_size == 's')
		return (strnlen(v, n) + 1);

	return (f->f_size - '0');
}

/*
 * Verify that 's' is a valid UTF-8 string.
 */
static int
bson_valid_utf8(const char *s, int len)
{
	while (len > 1) {
		const char *s0 = s;
		uint32_t u;

		if ((s = unicode_from_utf8(&u, s0)) == NULL)
			return (0);

		len -= (s - s0);
	}

	return (len == 1 && s[0] == 0);
}

/*
 * Verify that all tokens have valid values within max_off. Most bson types
 * admit any possible value (e.g. there is no invalid 64-bit value for
 * BSON_INT64), so at present we just check that all strings are valid UTF-8.
 * Return the end of the tokens (i.e., the start of next token), 0 if one of the
 * tokens is invalid, a value greater than max_off if the tokens are too
 * long, and a negative value if an encoded token size is negative.
 */
static off_t
bson_tokens_end(const char *src, const off_t v, int8_t type, off_t max_off)
{
	const bson_fmt_t *f;
	int32_t dsize = 0;

	if (v > max_off)
		return (v);

	off_t o = v;
	for (f = (const bson_fmt_t *)bson_format[type]; f->f_type; f++) {

		int32_t len = bson_token_size(f, src, max_off - o, &dsize);

		if (len < 0)
			return (len);

		o += len;
		if (o > max_off)
			return (o);

		if (f->f_kind == 's' && !bson_valid_utf8(src, len))
			return (0);

		src += len;
	}

	return (o);
}

/*
 * Encode a BSON value as described above.  Each BSON token is either
 * a pointer (f_type == 'p') or a word:  if it's a pointer, memmove()
 * the data; if it's a word, convert from native to BSON (LE) format.
 * Returns the number of destination bytes produced.
 */
static int32_t
bson_encode_ap(char *dst, int8_t type, va_list ap)
{
	char *dst0 = dst;
	const bson_fmt_t *f;
	int32_t dsize = 0;

	for (f = (const bson_fmt_t *)bson_format[type]; f->f_type; f++) {

		const void *src = va_arg(ap, void *);
		int32_t len = bson_token_size(f, src, SIZE_MAX, &dsize);

		if (dst0 != NULL) {
			if (f->f_type == 'p') {
				(void) memmove(dst, src, (size_t)len);
			} else {
				bson_move_word(dst, src, len);
			}
		}
		dst += len;
	}

	return (dst - dst0);
}

/*
 * Decode a BSON value as described above.  Each BSON token is either
 * a pointer (f_type == 'p') or a word:  if it's a pointer, store the
 * pointer; if it's a word, convert from BSON (LE) to native format.
 * Returns the number of source bytes consumed.
 */
static int32_t
bson_decode_ap(const char *src, int8_t type, va_list *ap)
{
	const char *src0 = src;
	const bson_fmt_t *f;
	int32_t dsize = 0;

	if (type < 0 || type >= BSON_TYPES + 2)
		return (-1);

	for (f = (const bson_fmt_t *)bson_format[type]; f->f_type; f++) {

		int32_t len = bson_token_size(f, src, SIZE_MAX, &dsize);

		if (ap != NULL) {
			void *dst = va_arg(*ap, void *);

			if (dst != NULL) {
				if (f->f_type == 'p') {
					*(const void **)dst = src;
				} else {
					bson_move_word(dst, src, len);
				}
			}
		}
		src += len;
	}

	return (src - src0);
}

/*
 * Varargs entry point for bson_encode_ap().
 */
static int32_t
bson_encode(char *dst, int8_t type, ...)
{
	va_list ap;
	int32_t len;

	va_start(ap, type);
	len = bson_encode_ap(dst, type, ap);
	va_end(ap);

	return (len);
}

/*
 * Varargs entry point for bson_decode_ap().
 */
static int32_t
bson_decode(const char *src, int8_t type, ...)
{
	va_list ap;
	int32_t len;

	va_start(ap, type);
	len = bson_decode_ap(src, type, &ap);
	va_end(ap);

	return (len);
}

/*
 * Return the first element in document d.
 */
static off_t
bson_first_element(bson_t *b, off_t d)
{
	return (d + sizeof (int32_t));
}

/*
 * Determine the type / name / value of the element starting at t,
 * and return end of element (which is also start of next element).
 * Assumes the document does not change between calls.
 */
static off_t
bson_parse_element(bson_t *b, off_t t, int8_t *tp, const char **np, off_t *vp)
{
	off_t e;

	if (b->b_buf[t] == 0)
		return (0);

	if ((e = bson_decode(b->b_buf + t, BSON_TYPE_NAME, tp, np)) == 0)
		return (0);
	*vp = t + e;

	if (*vp >= b->b_docsize ||
		(e = bson_decode_ap(b->b_buf + *vp, *tp, NULL)) < 0)
		return (0);
	e += *vp;

	return (e);
}

/*
 * Push (v, t) onto the BSON lookup stack.
 */
static void
bson_push(bson_t *b, off_t v, off_t t)
{
	int depth = ++b->b_depth;
	b->b_value[depth] = v;
	b->b_type[depth] = t;
}

/*
 * Pop (v, t) off of the BSON lookup stack.
 */
static void
bson_pop(bson_t *b, off_t *v, off_t *t)
{
	int depth = b->b_depth--;

	if (v != NULL)
		*v = b->b_value[depth];
	if (t != NULL)
		*t = b->b_type[depth];
}

/*
 * Get (v, t) from the top of the BSON lookup stack.
 */
static void
bson_top(const bson_t *b, off_t *v, off_t *t)
{
	int depth = b->b_depth;

	if (v != NULL)
		*v = b->b_value[depth];
	if (t != NULL)
		*t = b->b_type[depth];
}

/*
 * Get type from offset t in document.  offset == -1 refers to b_doctype.
 */
static int8_t
bson_get_type(const bson_t *b, off_t t)
{
	return (t < 0 ? b->b_doctype : (int8_t)b->b_buf[t]);
}

/*
 * Set type at offset t in document.  offset == -1 refers to b_doctype.
 */
static void
bson_set_type(bson_t *b, off_t t, int8_t type)
{
	if (t < 0)
		b->b_doctype = type;
	else
		b->b_buf[t] = type;
}

/*
 * Starting at offset v into b->b_buf, look for (dir = d, path = p).
 * If non-NULL, 'a' is the last component of p, and is being added.
 */
static int
bson_find_dp(bson_t *b, off_t v, off_t t, off_t d, const char *p, const char *a)
{
	int8_t type = bson_get_type(b, t);
	const char *n;
	off_t e;
	int m;

	if (b->b_depth + 1 + !!a >= BSON_MAX_DEPTH)
		return (EOVERFLOW);

	bson_push(b, v, t);

	if (v == d && p == NULL)
		return (0);

	if (type != BSON_OBJECT && type != BSON_ARRAY)
		return (ENOTDIR);

	if (v == d && p == a)
		return (0);

	for (t = bson_first_element(b, v);
	    (e = bson_parse_element(b, t, &type, &n, &v)) != 0; t = e) {

		if (type <= 0 || type >= BSON_TYPES)
			return (EBADF);

		if (e < d)		// d is somewhere after the next element
			continue;

		if (v <= d)		// d is somewhere within v
			return (bson_find_dp(b, v, t, d, p, a));

		if (p == NULL)		// no path left, item not found
			break;

		for (m = 0; n[m] != 0 && n[m] == p[m]; m++) // name == path?
			continue;

		if (n[m] != 0)		// no, keep looking
			continue;

		if (p[m] == 0)		// yes, push on BSON stack
			return (bson_find_dp(b, v, t, v, NULL, a));

		if (p[m] == b->b_sep)	// yes, strip component and keep going
			return (bson_find_dp(b, v, t, v, p + m + 1, a));
	}

	return (ENOENT);
}

/*
 * Find (d, p), using as much of the previous lookup stack as possible.
 * If non-NULL, 'a' is the last component of p, and is being added.
 */
static int
bson_find(bson_t *b, off_t d, const char *p, const char *a)
{
	off_t v, t;

	if (b->b_value[b->b_depth] == d && p == NULL)
		return (0);

	do {
		bson_pop(b, &v, &t);
	} while (v != d && b->b_depth >= 0);

	return (bson_find_dp(b, v, t, d, p, a));
}

/*
 * Like bson_first_element(), but returns negated offset so that
 * bson_next() can distinguish the first call.  Callers should treat
 * this value as an opaque token for iteration.
 */
off_t
bson_first(bson_t *b, off_t d)
{
	return (-bson_first_element(b, d));
}

/*
 * Return the next element after t, and decode its type / name / value.
 * bson_next() maintains the bson stack so that callers of bson_*(b, v, ...)
 * within a bson_next() iteration loop immediately succeed, rather than
 * searching for their place in the document, which ensures that bson_next()
 * iteration is linear rather than quadratic.  bson_next() is robust against
 * changes to the current element between calls, e.g. bson_set_*(b, v, ...).
 * It is also robust against intervening changes to the bson stack.
 * Callers should treat t as an opaque token for iteration.
 */
off_t
bson_next(bson_t *b, off_t t, int8_t *tp, const char **np, off_t *vp)
{
	off_t v, e, t0 = t;
	int8_t type;

	if (t0 < 0)
		t = -t;

	if ((e = bson_parse_element(b, t, &type, np, &v)) == 0)
		return (0);

	if (bson_find(b, v, NULL, NULL) != 0)
		return (0);

	if (t0 > 0 && bson_parse_element(b, t = e, &type, np, &v) == 0)
		return (0);

	bson_pop(b, NULL, NULL);
	bson_push(b, v, t);

	if (tp != NULL)
		*tp = type;
	if (vp != NULL)
		*vp = v;

	return (t);
}

/*
 * Initialize a bson context.  If 'buf' already contains a bson document,
 * 'type' specifies its type (BSON_OBJECT or BSON_ARRAY).  Otherwise, 'buf'
 * is uninitialized and 'type' should be BSON_NULL.  'size' is the size of buf,
 * 'sep' is the path separator, and 'f' is an optional error callback.
 */
void
bson_init(bson_t *b, char *buf, size_t size, vmem_t *vm, char sep, int8_t type,
    bson_err_f *f)
{
	assert((buf == NULL && size == 0 && vm != NULL) ||
	    (buf != NULL && vm == NULL));

	b->b_buf = buf;
	b->b_bufsize = size;
	b->b_vmem = vm;
	b->b_sep = sep;
	b->b_quote = '"';
	b->b_rdonly = 0;
	b->b_szlock = 0;
	b->b_doctype = type;
	if ((buf != NULL) && (size < sizeof (bson_empty)))
		// The error will be caught by bson_verify().
		b->b_docsize = 0;
	else
		b->b_docsize = bson_decode_ap(buf, type, NULL);
	b->b_errfunc = f;
	b->b_parse_err[0] = '\0';
	b->b_parse_line = 0;
	b->b_depth = -1;
	bson_push(b, 0, -1);
}

/*
 * Prohibit set, add, concat, remove, and set_buffer operations.
 */
void
bson_set_readonly(bson_t *b)
{
	b->b_rdonly = 1;
}

/*
 * Prohibit operations that change document size or offsets.
 *
 * This function makes it possible for iteration functions to fail fast if a
 * user supplied callback tries to modify the document in a way that invalidates
 * iteration. It is similar to bson_set_readonly(), but it allows same-type
 * modification of numeric values, and it can be turned off when iteration is
 * complete.
 */
void
bson_set_sizelock(bson_t *b, int v)
{
	b->b_szlock = v;
}

/*
 * Finish using a bson context, and free anything that's been allocated.
 */
void
bson_fini(bson_t *b)
{
	if (b->b_vmem != NULL)
		vmem_free(b->b_vmem, b->b_buf, b->b_bufsize);

	memset(b, 0, sizeof (*b));
}

/*
 * Grow b_buf to newsize.
 */
int
bson_resize(bson_t *b, size_t newsize)
{
	char *newbuf = NULL;

	assert(newsize >= b->b_bufsize);

	if (b->b_vmem != NULL)
		newbuf = vmem_alloc(b->b_vmem, newsize, VM_SLEEP);

	if (newbuf == NULL)
		return (-1);

	(void) memcpy(newbuf, b->b_buf, b->b_bufsize);
	vmem_free(b->b_vmem, b->b_buf, b->b_bufsize);

	b->b_buf = newbuf;
	b->b_bufsize = newsize;

	return (0);
}

/*
 * Insert a gap of size delta at offset v in a BSON document, and update
 * the sizes of all containing documents (i.e. add delta) accordingly.
 * This is necessary when adding a new element or resizing an existing one.
 */
static int
bson_gap(bson_t *b, off_t v, int32_t delta, int depth)
{
	char *vp;
	size_t docsize = (size_t)b->b_docsize;

	if (b->b_rdonly)
		return (EROFS);

	if (delta == 0)
		return (0);

	if (b->b_szlock)
		return (EBADF);

	if (docsize + delta > b->b_bufsize) {

		size_t newsize = docsize + delta;

		newsize += newsize >> 2;	// add 25% for future growth

		if (bson_resize(b, newsize) != 0)
			return (ENOMEM);
	}

	vp = b->b_buf + v;

	(void) memmove(vp + delta, vp, docsize - v);

	for (int d = depth; d >= 0; d--) {
		int8_t t = bson_get_type(b, b->b_type[d]);
		if (t == BSON_OBJECT || t == BSON_ARRAY) {
			char *doc = b->b_buf + b->b_value[d];
			bson_set_size(doc, bson_get_size(doc) + delta);
		}
	}

	b->b_docsize = (int32_t)docsize + delta;

	return (0);
}

/*
 * Determine whether (dir = d, path = p) exists. Optionally get the offset
 * and/or type of the value if it exists.
 */
int
bson_exists(bson_t *b, off_t d, const char *p, off_t *op, int8_t *type)
{
	int exists;
	off_t t;

	exists = (bson_find(b, d, p, NULL) == 0);
	if (exists) {
		bson_top(b, op, &t);
		if (type != NULL)
			*type = bson_get_type(b, t);
	}

	return (exists);
}

/*
 * Look for (dir = d, path = p); if found, sets *type and *op = value offset.
 */
int
bson_lookup(bson_t *b, off_t d, const char *p, off_t *op, int8_t *type)
{
	off_t t;
	int err;

	if ((err = bson_find(b, d, p, NULL)) != 0)
		return (bson_error(b, d, p, 0, err, __func__));

	bson_top(b, op, &t);

	if (type != NULL)
		*type = bson_get_type(b, t);

	return (0);
}

/*
 * Get value of (dir = d, path = p) into supplied args.
 */
int
bson_get(bson_t *b, off_t d, const char *p, off_t *op, int8_t type, ...)
{
	va_list ap;
	off_t v, t;
	int err;

	if ((err = bson_find(b, d, p, NULL)) != 0)
		return (bson_error(b, d, p, type, err, __func__));

	bson_top(b, &v, &t);

	if (bson_get_type(b, t) != type)
		return (bson_error(b, d, p, type, EPROTOTYPE, __func__));

	va_start(ap, type);
	(void) bson_decode_ap(b->b_buf + v, type, &ap);
	va_end(ap);

	if (op != NULL)
		*op = v;

	return (0);
}

/*
 * Set value of (dir = d, path = p) using supplied args.
 */
int
bson_set(bson_t *b, off_t d, const char *p, off_t *op, int8_t type, ...)
{
	va_list ap;
	off_t v, t;
	int32_t oldsize, newsize;
	int8_t otype;
	int err;

	if ((err = bson_find(b, d, p, NULL)) != 0)
		return (bson_error(b, d, p, type, err, __func__));

	bson_top(b, &v, &t);

	otype = bson_get_type(b, t);
	oldsize = bson_decode_ap(b->b_buf + v, otype, NULL); // decode old type

	va_start(ap, type);
	newsize = bson_encode_ap(NULL, type, ap);	// encode using new type
	va_end(ap);

	if (newsize < 0 || (newsize == 0 &&
	    ((const bson_fmt_t *)bson_format[type])->f_type != '\0'))
		return (EINVAL);

	if ((err = bson_gap(b, v + oldsize, newsize - oldsize, b->b_depth - 1)))
		return (bson_error(b, d, p, type, err, __func__));

	va_start(ap, type);
	bson_set_type(b, t, type);			// set new type
	(void) bson_encode_ap(b->b_buf + v, type, ap);	// encode new value
	va_end(ap);

	if (op != NULL)
		*op = v;

	return (0);
}

/*
 * Add element (dir = d, path = p) using supplied args.
 */
int
bson_add(bson_t *b, off_t d, const char *p, off_t *op, int8_t type, ...)
{
	va_list ap;
	int32_t newsize;
	const char *n = p;
	off_t v, t, o;
	int err;

	for (const char *s = p; *s != 0; s++)
		if (*s == b->b_sep)
			n = s + 1;

	if ((err = bson_find(b, d, p, n)) != 0)
		return (bson_error(b, d, p, type, err, __func__));

	va_start(ap, type);
	newsize = bson_encode_ap(NULL, type, ap);
	va_end(ap);

	if (newsize < 0 || (newsize == 0 &&
	    ((const bson_fmt_t *)bson_format[type])->f_type != '\0'))
		return (EINVAL);

	newsize += bson_encode(NULL, BSON_TYPE_NAME, &type, n);

	o = b->b_value[b->b_depth];		// o = containing object
	t = o + bson_get_size(b->b_buf + o) - 1; // new element goes at the end

	if ((err = bson_gap(b, t, newsize, b->b_depth)))
		return (bson_error(b, d, p, type, err, __func__));

	va_start(ap, type);
	v = t + bson_encode(b->b_buf + t, BSON_TYPE_NAME, &type, n);
	(void) bson_encode_ap(b->b_buf + v, type, ap);
	va_end(ap);

	bson_push(b, v, t);			// add frame for new element

	if (op != NULL)
		*op = v;

	return (0);
}

int
__attribute__((format(__printf__, 4, 0)))
bson_add_vsprintf(bson_t *b, off_t d, const char *p, const char *fmt,
    va_list ap)
{
	va_list aq;
	int32_t newsize;
	const char *n = p;
	off_t v, t, o;
	int8_t type = BSON_STRING;
	int32_t size = 1; // strlen("") + 1;
	int len;
	int err;

	for (const char *s = p; *s != 0; s++)
		if (*s == b->b_sep)
			n = s + 1;

	if ((err = bson_find(b, d, p, n)) != 0)
		return (bson_error(b, d, p, type, err, __func__));

	va_copy(aq, ap);
	len = vsnprintf(NULL, 0, fmt, aq);
	va_end(aq);

	if (len < 0)
		return (EINVAL);

	newsize = bson_encode(NULL, BSON_TYPE_NAME, &type, n);
	newsize += bson_encode(NULL, type, &size, "");
	newsize += len;

	o = b->b_value[b->b_depth];		// o = containing object
	t = o + bson_get_size(b->b_buf + o) - 1; // new element goes at the end

	if ((err = bson_gap(b, t, newsize, b->b_depth)))
		return (bson_error(b, d, p, type, err, __func__));

	size = len + 1;
	v = t + bson_encode(b->b_buf + t, BSON_TYPE_NAME, &type, n);
	o = v + bson_encode(b->b_buf + v, BSON_STRBUF, &size);

	va_copy(aq, ap);
	(void) vsnprintf(b->b_buf + o, (size_t)size, fmt, aq);
	va_end(aq);

	bson_push(b, v, t);			// add frame for new element

	return (0);
}

int
__attribute__((format(__printf__, 4, 5)))
bson_add_sprintf(bson_t *b, off_t d, const char *p, const char *fmt, ...)
{
	va_list ap;
	int err;

	va_start(ap, fmt);
	err = bson_add_vsprintf(b, d, p, fmt, ap);
	va_end(ap);

	return (err);
}

static inline int
bson_is_last(bson_t *b, off_t t)
{
	int8_t type;
	off_t v, e;
	const char *n;

	e = bson_parse_element(b, t, &type, &n, &v);

	return (e != 0 && b->b_buf[e] == 0);
}

/*
 * Remove element (dir = d, path = p).
 */
int
bson_remove(bson_t *b, off_t d, const char *p)
{
	off_t v, t;
	const char *n;
	int8_t type;
	int32_t oldsize;
	int err;

	if ((err = bson_find(b, d, p, NULL)) != 0)
		return (bson_error(b, d, p, 0, err, __func__));

	if (b->b_depth == 0)
		return (bson_error(b, d, p, b->b_doctype, EBUSY, __func__));

	bson_pop(b, &v, &t);

	type = bson_get_type(b, b->b_type[b->b_depth]);
	switch (type) {
	case BSON_OBJECT:
		break;
	case BSON_ARRAY:
		if (bson_is_last(b, t))
			break; // OK to remove the last element
		return (bson_error(b, d, p, type, ERANGE, __func__));
	default:
		return (bson_error(b, d, p, type, ENOTDIR, __func__));
        }

	oldsize = bson_decode(b->b_buf + t, BSON_TYPE_NAME, &type, &n);
	oldsize += bson_decode_ap(b->b_buf + v, type, NULL);

	if ((err = bson_gap(b, t + oldsize, 0 - oldsize, b->b_depth)))
		return (bson_error(b, d, p, type, err, __func__));

	return (0);
}

#ifndef BSON_ALTERNATE_BUILD
/*
 * Append to value of (dir = d, path = p) using supplied args.
 */
int
bson_concat(bson_t *b, off_t d, const char *p, int8_t type, ...)
{
	va_list ap;
	off_t v, off;
	int32_t oldsize, newsize, added_size;
	int32_t src_dsize = -1;
	int32_t dst_dsize = 0;
        const char *src_datap = NULL;
	char *dst;
	const bson_fmt_t *f;
        int is_string_data = 0;
	int err;

	if ((err = bson_find(b, d, p, NULL)) != 0)
		return (bson_error(b, d, p, type, err, __func__));

	bson_top(b, &v, &off);

	if (type != bson_get_type(b, off))
		return (EPROTOTYPE);

	dst = b->b_buf + v;
	va_start(ap, type);
	for (f = (const bson_fmt_t *)bson_format[type]; f->f_type; f++) {

		const void *src;

		/*
		 * Disallow concatenation if the token for the data pointer is
		 * not the final token, for example if BF_CODEWS.
		 */
		if (src_datap != NULL)
			return (EINVAL);

		dst += bson_token_size(f, dst, SIZE_MAX, &dst_dsize);

		/*
		 * If the token is fixed-size numeric, leave it alone. We can't
		 * append to it, and if it's a binary subtype, appending to the
		 * binary data won't change the subtype.
		 */
		if (f->f_kind == 'n' && f->f_size != 'd')
			continue;

		src = va_arg(ap, void *);
		(void) bson_token_size(f, src, SIZE_MAX, &src_dsize);

		if (f->f_type == 'p') {
			src_datap = src;
			is_string_data = (f->f_kind == 's');
			/*
			 * Disallow concatenation of documents.
			 */
			if (f->f_kind == 'd')
				return (EINVAL);
		}
	}
	va_end(ap);

	/*
	 * Concatenation is only supported for BSON pointer types whose values
	 * are prefixed with a size, for example BF_STRING, but not BF_CSTRING.
	 */
	if (src_datap == NULL || src_dsize == -1)
		return (EINVAL);

	oldsize = dst - (b->b_buf + v);
	added_size = src_dsize;
	if (is_string_data) {
		/*
		 * The size of the existing string includes the terminating NUL
		 * character, but concatenation will start on top of, not after,
		 * the terminating NUL.
		 */
		dst -= 1;
		added_size -= 1;
	}
	newsize = dst_dsize + added_size;
        off = dst - b->b_buf;

	if ((err = bson_gap(b, v + oldsize, added_size, b->b_depth - 1)))
		return (bson_error(b, d, p, type, err, __func__));

	bson_move_word(b->b_buf + v, (void *)&newsize, sizeof (int32_t));
	(void) memmove(b->b_buf + off, src_datap, (size_t)src_dsize);
	return (0);
}
#endif

int
bson_set_buffer(bson_t *b, off_t d, const char *p, off_t *op, int32_t size)
{
	off_t v, t;
	int32_t oldsize, newsize;
	int8_t otype;
        int8_t subtype = BSON_BIN_BINARY;
	int err;

	if ((err = bson_find(b, d, p, NULL)) != 0)
		return (bson_error(b, d, p, BSON_BINARY, err, __func__));

	bson_top(b, &v, &t);

	otype = bson_get_type(b, t);

	oldsize = bson_decode_ap(b->b_buf + v, otype, NULL); // decode old type
        newsize = bson_encode(NULL, BSON_BINARY, &size, &subtype, NULL);

	if ((err = bson_gap(b, v + oldsize, newsize - oldsize, b->b_depth - 1)))
		return (bson_error(b, d, p, BSON_BINARY, err, __func__));

	bson_set_type(b, t, BSON_BINARY);		// set new type
	v += bson_encode(b->b_buf + v, BSON_BUFFER, &size, &subtype);

	if (op != NULL)
		*op = v;

	return (0);
}

/*
 * Get the size of the BSON value encoding at the given offset, useless for
 * anything but a dump or bson_init() of type other than BSON_OBJECT or
 * BSON_ARRAY. Use bson_get_size() instead.
 */
int
bson_get_encoded_value_size(bson_t *b, off_t d, size_t *sizep)
{
	off_t v, t;
	size_t size;
	int8_t type;
	int err;

	if ((err = bson_find(b, d, NULL, NULL)) != 0)
		return (bson_error(b, d, NULL, 0, err, __func__));

	bson_top(b, &v, &t);

	type = bson_get_type(b, t);
	size = (size_t) bson_decode_ap(b->b_buf + v, type, NULL);

	if (sizep != NULL)
	    *sizep = size;

	return (0);
}

/*
 * Recursively verify document validity for scope js, starting at (t, n, v).
 */
static int
bson_verify_tree(bson_t *b, off_t t, const char *n, off_t v, off_t max_off,
    json_scope_t js, off_t *end_off)
{
	if (b->b_doctype == BSON_NULL)
		return (0);
	if (v > max_off || t >= max_off || v < 0 ||
	    (t < (off_t)sizeof (int32_t) && t != -1))
		return (EBADF);

	const char *tp = b->b_buf + t;
	const char *vp = b->b_buf + v;
	int8_t type = bson_get_type(b, t);
	int err;

	if (n != NULL) {
		if (n != tp + 1)
			return (EBADF);
		t = bson_tokens_end(tp, t, BSON_TYPE_NAME, v);
		if (t != v)
			return (EBADF);
		if (t == 0)
			return (EINVAL);
		if (b->b_sep != 0 && strchr(n, b->b_sep) != NULL)
			return (EINVAL);
	}

	if (type == BSON_OBJECT || type == BSON_ARRAY) {
		int a = (type == BSON_ARRAY) ? 0 : -1;
		off_t e;

		if ((off_t)(v + sizeof (bson_empty)) > max_off)
			return (EBADF);
		int32_t s = bson_get_size(b->b_buf + v);
		if (s < (int32_t) sizeof (bson_empty))
			return (EBADF);
		*end_off = v + s;
		if (*end_off > max_off)
			return (EBADF);

		for (t = bson_first_element(b, v);
		    t < *end_off && b->b_buf[t] != 0; t = e) {
			if ((v = bson_tokens_end(b->b_buf + t, t,
			    BSON_TYPE_NAME, *end_off)) == 0)
				return (EINVAL);
			if ((err = bson_verify_tree(b, t, NULL, v, *end_off, js,
			    &e)) != 0)
				return (err);
			if (a >= 0 && strtol(b->b_buf + t + 1, NULL, 10) != a++)
				return (ERANGE);
		}
		if (t + 1 != *end_off)
			return (EBADF);
	} else {
		if (type <= 0 || type >= BSON_TYPES)
			return (EBADF);
		if (json_scope[type] > js && js != JSON_TYPED)
			return (EDOM);
		*end_off = bson_tokens_end(vp, v, type, max_off);
		if (*end_off == 0)
			return (EINVAL);
		if (*end_off > max_off)
			return (EBADF);
		if (*end_off < 0)
			return (EBADF);
	}

	return (0);
}

/*
 * Verify validity of document (dir = d, path = p) for scope js.
 */
int
bson_verify(bson_t *b, off_t d, const char *p, json_scope_t js)
{
	off_t v, t;
	int8_t type;
	int err;

	if ((err = bson_find(b, d, p, NULL)) != 0)
		return (bson_error(b, d, p, 0, err, __func__));

	bson_top(b, &v, &t);

	type = bson_get_type(b, t);

	off_t end_off;
	if ((err = bson_verify_tree(b, t, NULL, v, b->b_bufsize, js, &end_off))
	    != 0)
		return (bson_error(b, d, p, type, err, __func__));

	return (0);
}

/*
 * Print BSON value v, with token format f, into JSON buffer j of size z.
 */
static char *
bson_print_value(const bson_fmt_t *f, const void *v, int32_t dsize,
    char q, char *j, size_t z)
{
	char dbuf[64];
	int dlen;

	switch (f->f_type) {

	case 'i':
		switch (f->f_size) {
		case '1':
			return (j + snprintf(j, z, "%" PRId8, *(int8_t *)v));
		case '4':
			return (j + snprintf(j, z, "%" PRId32, *(int32_t *)v));
		case '8':
			return (j + snprintf(j, z, "%" PRId64, *(int64_t *)v));
		}
		break;

	case 'd':
		/*
		 * Doubles must always be printed with either a decimal point
		 * or an 'e' so that they can be distinguished from integers;
		 * otherwise BSON/JSON conversion could lose type information.
		 * Sadly, there is no way in C to say "print a double that
		 * always has a decimal point, but without gratuitous trailing
		 * zeroes."  So, we use %.16g and tack on '.0' if necessary.
		 */
		dlen = snprintf(dbuf, sizeof (dbuf), "%.16g", *(double *)v);
		j += snprintf(j, z, "%s", dbuf);
		for (int i = 0; i < dlen; i++)
			if (dbuf[i] == '.' || dbuf[i] == 'e')
				return (j);
		return (j + snprintf(j, z, "%s", ".0"));

	case 'p':
		if (f->f_kind == 's') {
			j += json_string_from_utf8(z ? j : NULL, q, v, dsize);
		} else {
			size_t len;
			const uint8_t *val = v;
			for (int i = 0; i < dsize; i++) {
				len = (size_t)snprintf(j, z, "%s%d%s",
					i == 0 ? "<" : ", ", *(val++),
					i == dsize - 1 ? ">" : "");
				if (z > len)
					z -= len;
				else
					z = 0;
				j += len;
			}
		}
		break;
	}

	return (j);
}

/*
 * Print BSON element (t, n, v) into JSON buffer j of size z, using output
 * format suitable for scope js.
 */
static char *
bson_print(bson_t *b, off_t t, const char *n, off_t v, int depth,
    json_scope_t js, json_format_t jf, char *j, size_t z)
{
	char q = b->b_quote;
	const char *vp = b->b_buf + v;
	int8_t type = bson_get_type(b, t);
	int comma = 0;

	if (depth == 0 && js == JSON_BSON) {
		size_t size = (size_t) bson_decode_ap(vp, type, NULL);
		if (size <= z)
			memmove(j, vp, size);
		return (j + size);
	}

	if (jf == JSON_PRETTY) {
		for (int d = 0; d < depth; d++)
			j += snprintf(j, z, "\t");
	}

	if (js == JSON_TYPED)
		j += snprintf(j, z, "(%s) ", bson_type_name[type]);

	if (n != NULL) {
		j += json_string_from_utf8(z ? j : NULL, q, n, strlen(n) + 1);
		j += snprintf(j, z, "%s", jf == JSON_PRETTY ? ": " : ":");
	}

	if (type == BSON_OBJECT || type == BSON_ARRAY) {
		int8_t t0;
		off_t e;
		j += snprintf(j, z, "%c", type == BSON_OBJECT ? '{' : '[');
		for (t = bson_first_element(b, v);
		    (e = bson_parse_element(b, t, &t0, &n, &v)) != 0; t = e) {
			if (comma++)
				j += snprintf(j, z, ",");
			if (jf == JSON_PRETTY)
				j += snprintf(j, z, "\n");
			if (js <= JSON_PRINTABLE && type == BSON_ARRAY)
				n = NULL;
			j = bson_print(b, t, n, v, depth + 1, js, jf, j, z);
		}
		if (jf == JSON_PRETTY) {
			j += snprintf(j, z, "\n");
			for (int d = 0; d < depth; d++)
				j += snprintf(j, z, "\t");
		}
		j += snprintf(j, z, "%c", type == BSON_OBJECT ? '}' : ']');
	} else if (type == BSON_BOOLEAN) {
		j += snprintf(j, z, "%s", *vp ? json_true : json_false);
	} else if (type == BSON_NULL) {
		j += snprintf(j, z, "%s", json_null);
	} else {
		const bson_fmt_t *f;
		int32_t dsize = 0;

		for (f = (const bson_fmt_t *)bson_format[type];
		    f->f_type; f++) {
			int32_t len = bson_token_size(f, vp, SIZE_MAX, &dsize);
			char buf[8] __attribute__((aligned(16)));
			void *a = buf;
			if (f->f_type == 'p') {
				a = (char *)vp;
			} else {
				bson_move_word(a, vp, len);
			}
			vp += len;
			if (js <= JSON_PRINTABLE && f->f_kind == 'd')
				continue;
			if (comma++) {
				j += snprintf(j, z,
				    (jf == JSON_PRETTY ? ", " : ","));
			}
			j = bson_print_value(f, a, len, q, j, z);
		}
	}

	if (depth == 0) {
		if (jf == JSON_PRETTY)
			j += snprintf(j, z, "\n");
		j += 1;	// +1 for terminating null
	}

	return (j);
}

/*
 * Replace the value of (dir = d, path = p) with the content of JSON object j.
 */
int
bson_from_json(bson_t *b, off_t d, const char *p, json_scope_t js,
    const char *j, json_parse_cb *cb, void *arg)
{
	int err, saved_errno;

	if (js == JSON_BSON)
		return (bson_set(b, d, p, NULL, BSON_OBJECT, j));

	if (js == JSON_TYPED)		// we could add this if it's useful
		return (bson_error(b, d, p, 0, ENOTSUP, __func__));

	if ((err = bson_find(b, d, p, NULL)) != 0)
		return (bson_error(b, d, p, 0, err, __func__));

	b->b_parse_line = 1;
	b->b_parse_err[0] = '\0';

	saved_errno = errno;
	err = json_parse(b, &j, b->b_quote, -1, 0, cb, arg);
	errno = saved_errno;

	if (err == 0 && *j != '\0')
		err = E2BIG;

	(void) snprintf(b->b_parse_err, sizeof (b->b_parse_err), "%.*s",
	    (int)sizeof (b->b_parse_err) - 1, j);

	if (err)
		err = bson_error(b, d, p, 0, err, __func__);

	b->b_parse_line = 0;

	return (err);
}

/*
 * Convert BSON document (dir = d, path = p) into JSON text with scope js.
 * j is the JSON buffer, bufsize is its size, and *jsize is set to the size
 * required.  This is typically invoked twice: once with j = NULL, bufsize = 0
 * to determine the size, then again with j large enough to hold the result.
 */
int
bson_to_json(bson_t *b, off_t d, const char *p, json_scope_t js,
    json_format_t jf, char *j, size_t bufsize, size_t *jsize)
{
	off_t v, t;
	int8_t type;
	int err;

	*jsize = 0;

	if ((err = bson_find(b, d, p, NULL)) != 0)
		return (bson_error(b, d, p, 0, err, __func__));

	bson_top(b, &v, &t);

	type = bson_get_type(b, t);

	off_t end_off;
	if ((err = bson_verify_tree(b, t, NULL, v, b->b_bufsize, js, &end_off))
	    != 0)
		return (bson_error(b, d, p, type, err, __func__));

	*jsize = (size_t)(bson_print(b, t, NULL, v, 0, js, jf, j, 0) - j);

	if (*jsize > bufsize) {
		if (bufsize != 0)
			return (bson_error(b, d, p, type, ENOMEM, __func__));
		return (0);
	}

	(void) bson_print(b, t, NULL, v, 0, js, jf, j, *jsize);

	return (0);
}
