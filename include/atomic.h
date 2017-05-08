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

#ifndef	ATOMIC_H
#define	ATOMIC_H

#include <stdint.h>

#if defined(__i386__) || defined(__x86_64__)
#include <emmintrin.h>
#endif

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Auto-generate inline functions for all atomics of the following forms:
 *
 * atomic_{add,sub,or,xor,and,nand}_{8,16,32,64}{,_ov,_nv}(ptr, value);
 * atomic_{inc,dec}_{8,16,32,64}{,_ov,_nv}(ptr, value);
 * atomic_cas_{8,16,32,64,ptr}(ptr, old, new);
 *
 * The _ov() and _nv() variants return the old and new values, respectively.
 * With no suffix, the return type is void.  For example:
 *
 * uint32_t atomic_add_32_nv(uint32_t *p, uint32_t v) => return (*p += v);
 *
 * It's a bit off-putting to use macros to generate these functions,
 * but it's a lot less error-prone -- and a lot easier to modify -- than
 * a giant list of 101 hand-coded functions.  (It really is 101 functions:
 * 6 (add etc) * 4 * 3 + 2 (inc/dec) * 4 * 3 + 5 (cas) = 72 + 24 + 5 = 101.)
 */
#define	ATOMIC_OP_SIZE(op, b)						\
static inline void							\
__attribute__((always_inline))						\
atomic_##op##_##b(uint##b##_t *p, uint##b##_t v)			\
{									\
	(void)__sync_fetch_and_##op(p, v);				\
}									\
static inline uint##b##_t						\
__attribute__((always_inline))						\
atomic_##op##_##b##_ov(uint##b##_t *p, uint##b##_t v)			\
{									\
	return (__sync_fetch_and_##op(p, v));				\
}									\
static inline uint##b##_t						\
__attribute__((always_inline))						\
atomic_##op##_##b##_nv(uint##b##_t *p, uint##b##_t v)			\
{									\
	return (__sync_##op##_and_fetch(p, v));				\
}

#define	ATOMIC_ALIAS_SIZE(alias, op, v, b)				\
static inline void							\
__attribute__((always_inline))						\
atomic_##alias##_##b(uint##b##_t *p)					\
{									\
	(void)__sync_fetch_and_##op(p, v);				\
}									\
static inline uint##b##_t						\
__attribute__((always_inline))						\
atomic_##alias##_##b##_ov(uint##b##_t *p)				\
{									\
	return (__sync_fetch_and_##op(p, v));				\
}									\
static inline uint##b##_t						\
__attribute__((always_inline))						\
atomic_##alias##_##b##_nv(uint##b##_t *p)				\
{									\
	return (__sync_##op##_and_fetch(p, v));				\
}

#define	ATOMIC_CAS_SIZE(b)						\
static inline uint##b##_t						\
__attribute__((always_inline))						\
atomic_cas_##b(volatile uint##b##_t *p, uint##b##_t o, uint##b##_t n)	\
{									\
	return (__sync_val_compare_and_swap(p, o, n));			\
}

#define	ATOMIC_ALIAS(alias, op, v)					\
ATOMIC_ALIAS_SIZE(alias, op, v, 8)					\
ATOMIC_ALIAS_SIZE(alias, op, v, 16)					\
ATOMIC_ALIAS_SIZE(alias, op, v, 32)					\
ATOMIC_ALIAS_SIZE(alias, op, v, 64)

#define	ATOMIC_OP(op)							\
ATOMIC_OP_SIZE(op, 8)							\
ATOMIC_OP_SIZE(op, 16)							\
ATOMIC_OP_SIZE(op, 32)							\
ATOMIC_OP_SIZE(op, 64)

ATOMIC_OP(add)
ATOMIC_OP(sub)
ATOMIC_OP(or)
ATOMIC_OP(xor)
ATOMIC_OP(and)
ATOMIC_OP(nand)

ATOMIC_ALIAS(inc, add, 1)
ATOMIC_ALIAS(dec, sub, 1)

ATOMIC_CAS_SIZE(8)
ATOMIC_CAS_SIZE(16)
ATOMIC_CAS_SIZE(32)
ATOMIC_CAS_SIZE(64)

/*
 * GCC supports __int128 extension to generate cmpxchg16b on x86_64, but there
 * is no uint128_t posix type support yet so we can't use the macro expansion.
 */
#if defined(__x86_64__)
static inline __int128
__attribute__((always_inline))
atomic_cas_128(volatile __int128 *p, __int128 o, __int128 n)
{
	return (__sync_val_compare_and_swap(p, o, n));
}
#endif

/*
 * Unfortunately, ANSI C casting rules are broken in that foo_t ** cannot
 * be automatically converted to void **, so we declare 'p' as void * here.
 */
static inline void *
__attribute__((always_inline))
atomic_cas_ptr(volatile void *p, void *o, void *n)
{
	return (__sync_val_compare_and_swap((void **)p, o, n));
}


/*
 * Barriers
 */

#if defined(__i386__) || defined(__x86_64__)

static inline void
__attribute__((always_inline))
mem_lfence(void)
{
	_mm_lfence();
}

static inline void
__attribute__((always_inline))
mem_sfence(void)
{
	_mm_sfence();
}

static inline void
__attribute__((always_inline))
mem_mfence(void)
{
	_mm_mfence();
}

#elif defined(__arm__)

static inline void
__attribute__((always_inline))
mem_lfence(void)
{
	asm("dmb");
}

static inline void
__attribute__((always_inline))
mem_sfence(void)
{
	asm("dmb");
}

static inline void
__attribute__((always_inline))
mem_mfence(void)
{
	asm("dmb");
}

#else
#error "unknown arch"
#endif  // defined(__i386__) || defined(__x86_64__)


#ifdef	__cplusplus
}
#endif

#endif	/* ATOMIC_H */
