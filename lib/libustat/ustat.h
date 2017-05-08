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

#ifndef _USTAT_H
#define	_USTAT_H

#include <stdint.h>
#include <stdio.h>
#include <fcntl.h>
#include <time.h>
#include <units.h>

#ifdef	__cplusplus
extern "C" {
#endif

#define	USTAT_VERSION	1

typedef struct bson bson_t;
typedef void ustat_struct_t;
typedef struct ustat_handle ustat_handle_t;
typedef int ustat_walk_f(ustat_handle_t *, ustat_struct_t *, void *);

typedef enum ustat_conf {
	USTAT_CONF_PATH_MAX,
	USTAT_CONF_NAME_MAX,
	USTAT_CONF_XLEN_MAX,
} ustat_conf_t;

typedef struct ustat_unit {
	uint64_t usu_mult;
	const char *usu_suff;
} ustat_unit_t;

typedef enum ustat_type {
	USTAT_TYPE_INT8,
	USTAT_TYPE_INT16,
	USTAT_TYPE_INT32,
	USTAT_TYPE_INT64,
	USTAT_TYPE_UINT8,
	USTAT_TYPE_UINT16,
	USTAT_TYPE_UINT32,
	USTAT_TYPE_UINT64,
	USTAT_TYPE_SIZE, /* uint64_t regardless of word size, prints with BKM */
	USTAT_TYPE_CLOCK,
	USTAT_TYPE_TOD,
	USTAT_TYPE_DELTA,
	USTAT_TYPE_STRING,
	USTAT_TYPE_BYTES,
	USTAT_TYPE_ARRAY_U64, /* array of (aligned) uint64_t vals */
	USTAT_TYPE_UUID,
	USTAT_TYPE_MAX
} ustat_type_t;

/*
 * Note: ustat_value_t instances should always be aligned, and must never cross
 *       a cache line boundary on x86.  See the note for x86's implementation of
 *       USTAT_DECLARE_SET_FNS below for why.
 */
typedef union ustat_value {
        int8_t usv_i8;
        int16_t usv_i16;
        int32_t usv_i32;
        int64_t usv_i64;
        uint8_t usv_u8;
        uint16_t usv_u16;
        uint32_t usv_u32;
        uint64_t usv_u64;
        double usv_dbl;
        uint8_t *usv_buf;
        uint64_t *usv_buf_u64;
} ustat_value_t;

typedef struct ustat_named {
	const char *usn_name;
	ustat_type_t usn_type;
	uint32_t usn_xlen;
	void *usn_data;
} ustat_named_t;

typedef int (*ustat_export_bson_t)(ustat_struct_t *, int, bson_t *, off_t);

typedef struct ustat_class {
	const char *usc_name;
	ustat_struct_t *(*usc_ctor)(ustat_handle_t *,
	    const char *, const char *, int, const ustat_struct_t *, void *);
	int (*usc_dtor)(ustat_handle_t *, void *);
	ustat_export_bson_t usc_bson;
} ustat_class_t;

/*
 * The ustat_*64_t types are used internally for copying ustats b/w systems.
 * Their size must always match a 64-bit target version of ustat_*_t.
 */
typedef union ustat_value64 {
        int8_t usv_i8;
        int16_t usv_i16;
        int32_t usv_i32;
        int64_t usv_i64;
        uint8_t usv_u8;
        uint16_t usv_u16;
        uint32_t usv_u32;
        uint64_t usv_u64;
        double usv_dbl;
        uint64_t usv_buf;
        uint64_t usv_buf_u64;
} ustat_value64_t;

typedef struct ustat_named64 {
	uint64_t usn_name;
	ustat_type_t usn_type;
	uint32_t usn_xlen;
	uint64_t usn_data;
} ustat_named64_t;

typedef struct ustat_class64 {
	uint64_t usc_name;
	uint64_t usc_ctor;
	uint64_t usc_dtor;
	uint64_t usc_bson;
} ustat_class64_t;

typedef struct ustat_mbuf {
	const void *usm_data;
	size_t usm_size;
} ustat_mbuf_t;

extern ustat_handle_t *ustat_open_proc(int, pid_t, int);
extern ustat_handle_t *ustat_open_file(int, const char *, int);
extern ustat_handle_t *ustat_open_mem(int, const char *);
extern void ustat_close(ustat_handle_t *);

extern ssize_t ustat_conf(ustat_handle_t *, ustat_conf_t);
extern pid_t ustat_pid(ustat_handle_t *);
extern const char *ustat_comm(ustat_handle_t *);
extern const char *ustat_args(ustat_handle_t *);

extern ustat_named_t *ustat_lookup(ustat_handle_t *,
    const char *, const char *, const char *);

extern ustat_struct_t *ustat_lookup_struct(ustat_handle_t *,
    const char *, const char *);

extern int ustat_walk(ustat_handle_t *,
    const char *, ustat_walk_f *, void *);

extern const ustat_class_t ustat_class_misc;

extern ustat_struct_t *ustat_insert(ustat_handle_t *, const char *,
    const char *, const ustat_class_t *, int, const ustat_struct_t *, void *);

#define	USTAT_DEBUG_ABORT	0x01000000	/* abort() on caller errors */
#define	USTAT_DEBUG_VERBOSE	0x02000000	/* display errors to stderr */

#define	USTAT_RETAIN_MAPPINGS	0x04000000	/* keep stats mapped on close */
#define	USTAT_RETAIN_DELTA	0x08000000	/* keep delta data on snap */

#define	USTAT_PATTERN		0x10000000	/* path is a mkstemp pattern */

#define	USTAT_OFLAGS		0xFF000000	/* mask of libustat oflags */

extern int ustat_delete(ustat_struct_t *);
extern int ustat_update(ustat_handle_t *);

extern ustat_struct_t *ustat_snapshot(ustat_struct_t *);
extern ustat_struct_t *ustat_previous(ustat_struct_t *);

extern const ustat_class_t *ustat_cname_to_class(const char *cname);
extern void ustat_import(ustat_struct_t *, ustat_named_t *, void *);
extern void ustat_importv(ustat_struct_t *, int, const ustat_struct_t *);
extern int ustat_import_mbuf(ustat_handle_t *, const ustat_mbuf_t *);
extern void ustat_export(ustat_struct_t *, const ustat_named_t *, void *);
extern void ustat_exportv(ustat_struct_t *, int, ustat_struct_t *);
extern int ustat_export_bson(ustat_struct_t *, const ustat_named_t *, bson_t *,
    off_t);
extern int ustat_exportv_bson(ustat_struct_t *, int, bson_t *, off_t);

extern int ustat_getnnames(ustat_struct_t *);
extern ustat_named_t *ustat_getprev(ustat_struct_t *, ustat_named_t *);
extern ustat_named_t *ustat_getnext(ustat_struct_t *, ustat_named_t *);
extern const char *ustat_getgname(ustat_struct_t *);
extern const char *ustat_getcname(ustat_struct_t *);
extern void *ustat_getprivate(ustat_struct_t *);
extern uint64_t ustat_getctime(ustat_struct_t *);
extern uint64_t ustat_getatime(ustat_struct_t *);
extern void ustat_getmbuf(ustat_struct_t *, ustat_mbuf_t *);

extern const ustat_unit_t ustat_unit_size;
extern const ustat_unit_t ustat_unit_time;
extern const ustat_unit_t ustat_unit_iops;
extern const ustat_unit_t ustat_unit_tput;

extern int ustat_fprintf_unit(FILE *, int, uint64_t, const ustat_unit_t *);
extern int ustat_fprintf(ustat_handle_t *, FILE *, int, const ustat_named_t *);
extern int ustat_printf(ustat_handle_t *, int, const ustat_named_t *);

extern ustat_type_t ustat_str2type(const char *);
extern const char *ustat_type2str(ustat_type_t);

extern int ustat_error(const ustat_handle_t *, int, const char *, ...);
extern void *ustat_null(const ustat_handle_t *, int, const char *, ...);

/*
 * USTAT_CHECK_TYPE() verifies that the ustat_named_t's type matches the
 * expected type.  Since there is overhead, and these are speed-critical
 * functions, this check is only performed if one defines USTAT_DEBUG.
 */

extern void ustat_check_type(const ustat_struct_t *s, const ustat_named_t *n,
    ustat_type_t min_type, ustat_type_t max_type);

#if defined(USTAT_DEBUG)
#define USTAT_CHECK_TYPE(s, n, min_type, max_type)	\
	ustat_check_type(s, n, min_type, max_type)
#else
#define USTAT_CHECK_TYPE(s, n, min_type, max_type)
#endif

/*
 * ustat named get/set functions.  Naming convention:
 *
 *   {type}
 *   ustat_get_{stype}(ustat_struct_t *s, const ustat_named_t *n);
 *
 *   void
 *   ustat_[atomic_]{set,add,sub}_{stype}(ustat_struct_t *s, ustat_named_t *n,
 *                                        {type} v);
 *
 *   void
 *   ustat_[atomic_]{clr,inc,dec}_{stype}(ustat_struct_t *s, ustat_named_t *n);
 *
 * where:
 *
 *     {stype} is one of: i8, i16, i32, i64, u8, u16, u32, u64
 *     {type} is the stdint equivalent, e.g. int8_t, int16_t, ...
 *
 * e.g.
 *
 *   uint64_t ustat_get_u64(ustat_struct_t *s, ustat_named_t *n);
 *
 *   void ustat_set_u64(ustat_struct_t *s, ustat_named_t *n, uint64_t v);
 *   void ustat_atomic_set_u64(ustat_struct_t *s, ustat_named_t *n, uint64_t v);
 *   void ustat_add_u64(ustat_struct_t *s, ustat_named_t *n, uint64_t v);
 *   void ustat_sub_u64(ustat_struct_t *s, ustat_named_t *n, uint64_t v);
 *
 *   void ustat_clr_u64(ustat_struct_t *s, ustat_named_t *n);
 *   void ustat_atomic_clr_u64(ustat_struct_t *s, ustat_named_t *n);
 *   void ustat_inc_u64(ustat_struct_t *s, ustat_named_t *n);
 *   void ustat_dec_u64(ustat_struct_t *s, ustat_named_t *n);
 */

/* Generates a ustat trinary operator function */
#define USTAT_DECLARE_TOP_FN(t, tn, min_type, max_type, op, opsym)	\
									\
static inline void							\
__attribute__((always_inline))						\
ustat_##op##_##tn(ustat_struct_t *s, ustat_named_t *n, t v)		\
{									\
	ustat_value_t *p = n->usn_data;					\
	USTAT_CHECK_TYPE(s, n, min_type, max_type);			\
	p->usv_##tn opsym v;						\
}


/* Generates a ustat atomic trinary operator function */
#define USTAT_DECLARE_ATOMIC_TOP_FN(t, tn, min_type, max_type, op)	\
static inline void							\
__attribute__((always_inline))						\
ustat_atomic_##op##_##tn(ustat_struct_t *s, ustat_named_t *n, t v)	\
{									\
	ustat_value_t *p = n->usn_data;					\
	USTAT_CHECK_TYPE(s, n, min_type, max_type);			\
	(void)__sync_fetch_and_##op(&p->usv_##tn, v);			\
}


/*
 * Generates the ustat_[atomic_]set_*() functions.
 *
 * Intel guarantees that stores up to 64-bits that fit within a single CL are
 * atomic on P6 and newer processors.  Therefore, ustat_atomic_set_*() for
 * x86-64 use the assignment version for perf. reasons.  The x86-32 path could
 * also be implemented this way as long as one could guarantee that the
 * assignment resulted in a single 64-bit store that meets the above
 * constraints, however x86-32 is deprecated so there's no point.
 */
#if defined(__x86_64__)

#define USTAT_DECLARE_SET_FNS(t, tn, min_type, max_type)	\
USTAT_DECLARE_TOP_FN(t, tn, min_type, max_type, set, =)		\
USTAT_DECLARE_TOP_FN(t, tn, min_type, max_type, atomic_set, =)

#else

#define USTAT_DECLARE_SET_FNS(t, tn, min_type, max_type)	\
								\
USTAT_DECLARE_TOP_FN(t, tn, min_type, max_type, set, =)		\
								\
static inline void						\
__attribute__((always_inline))					\
ustat_atomic_set_##tn(ustat_struct_t *s, ustat_named_t *n, t v)	\
{								\
	ustat_value_t *p = n->usn_data;				\
	USTAT_CHECK_TYPE(s, n, min_type, max_type);		\
	(void)__sync_lock_test_and_set(&p->usv_##tn, v);	\
}

#endif  /* defined(__x86_64__) */


/* Generates the ustat_[atomic_]clr_*() functions. */
#define USTAT_DECLARE_CLR_FNS(t, tn)				\
								\
static inline void						\
__attribute__((always_inline))					\
ustat_clr_##tn(ustat_struct_t *s, ustat_named_t *n)		\
{								\
	ustat_set_##tn(s, n, 0);				\
}								\
								\
static inline void						\
__attribute__((always_inline))					\
ustat_atomic_clr_##tn(ustat_struct_t *s, ustat_named_t *n)	\
{								\
	ustat_atomic_set_##tn(s, n, 0);				\
}


/* Generates the ustat trinary operator functions */
#define USTAT_DECLARE_TOP_FNS(t, tn, min_type, max_type, op, opsym)	\
USTAT_DECLARE_TOP_FN(t, tn, min_type, max_type, op, opsym)		\
USTAT_DECLARE_ATOMIC_TOP_FN(t, tn, min_type, max_type, op)


/* Generates the ustat binary operator functions */
#define USTAT_DECLARE_BOP_FNS(t, tn, op, iop)			\
								\
static inline void						\
__attribute__((always_inline))					\
ustat_atomic_##op##_##tn(ustat_struct_t *s, ustat_named_t *n)	\
{								\
	ustat_atomic_##iop##_##tn(s, n, 1);			\
}								\
								\
static inline void						\
__attribute__((always_inline))					\
ustat_##op##_##tn(ustat_struct_t *s, ustat_named_t *n)		\
{								\
	ustat_##iop##_##tn(s, n, 1);				\
}


/* Generates a ustat_get_*() function */
#define USTAT_DECLARE_GET_FN(t, tn, min_type, max_type)		\
								\
static inline t							\
__attribute__((always_inline))					\
ustat_get_##tn(const ustat_struct_t *s, const ustat_named_t *n)	\
{								\
	ustat_value_t *p = n->usn_data;				\
	USTAT_CHECK_TYPE(s, n, min_type, max_type);		\
	return (p->usv_##tn);					\
}


/* Generates all of the ustat functions for a given type */
#define USTAT_DECLARE_FNS(t, tn, min_type, max_type)		\
USTAT_DECLARE_TOP_FNS(t, tn, min_type, max_type, add, +=)	\
USTAT_DECLARE_TOP_FNS(t, tn, min_type, max_type, sub, -=)	\
USTAT_DECLARE_BOP_FNS(t, tn, inc, add)				\
USTAT_DECLARE_BOP_FNS(t, tn, dec, sub)				\
USTAT_DECLARE_SET_FNS(t, tn, min_type, max_type)		\
USTAT_DECLARE_CLR_FNS(t, tn)					\
USTAT_DECLARE_GET_FN(t, tn, min_type, max_type)


/* Generates the ustat functions for all of the integer types */
USTAT_DECLARE_FNS(int8_t,   i8, USTAT_TYPE_INT8,  USTAT_TYPE_INT8)
USTAT_DECLARE_FNS(int16_t, i16, USTAT_TYPE_INT16, USTAT_TYPE_INT16)
USTAT_DECLARE_FNS(int32_t, i32, USTAT_TYPE_INT32, USTAT_TYPE_INT32)
USTAT_DECLARE_FNS(int64_t, i64, USTAT_TYPE_INT64, USTAT_TYPE_INT64)

USTAT_DECLARE_FNS(uint8_t,   u8, USTAT_TYPE_UINT8,  USTAT_TYPE_UINT8)
USTAT_DECLARE_FNS(uint16_t, u16, USTAT_TYPE_UINT16, USTAT_TYPE_UINT16)
USTAT_DECLARE_FNS(uint32_t, u32, USTAT_TYPE_UINT32, USTAT_TYPE_UINT32)
USTAT_DECLARE_FNS(uint64_t, u64, USTAT_TYPE_UINT64, USTAT_TYPE_DELTA)

extern void ustat_atomic_set_clock(ustat_struct_t *, ustat_named_t *,
    const struct timespec *);
extern void ustat_set_clock(ustat_struct_t *, ustat_named_t *,
    const struct timespec *);
extern void ustat_atomic_set_tod(ustat_struct_t *, ustat_named_t *,
    const struct timeval *);
extern void ustat_set_tod(ustat_struct_t *, ustat_named_t *,
    const struct timeval *);
extern void ustat_set_string(ustat_struct_t *, ustat_named_t *, const char *);
extern void ustat_set_bytes(ustat_struct_t *, ustat_named_t *, const uint8_t *,
    size_t);
extern void ustat_set_array_u64(ustat_struct_t *, ustat_named_t *,
    const uint64_t *, size_t);
extern void ustat_set_uuid(ustat_struct_t *, ustat_named_t *,
    const uint8_t *);

extern void ustat_get_clock(ustat_struct_t *,
    const ustat_named_t *, struct timespec *);
extern void ustat_get_tod(ustat_struct_t *,
    const ustat_named_t *, struct timeval *);
extern const char *ustat_get_str(ustat_struct_t *, const ustat_named_t *);
extern const uint8_t *ustat_get_bytes(ustat_struct_t *, const ustat_named_t *);
extern const uint64_t *ustat_get_array_u64(ustat_struct_t *,
    const ustat_named_t *);
extern void ustat_get_uuid(ustat_struct_t *, const ustat_named_t *,
    uint8_t *);

#ifdef	__cplusplus
}
#endif

#endif	/* _USTAT_H */
