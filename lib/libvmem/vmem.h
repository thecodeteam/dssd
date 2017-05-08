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

#ifndef _VMEM_H
#define	_VMEM_H

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>
#include <unuma.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Unified vmem flags
 */
typedef enum vmem_flag {
	/*
	 * Allocation sleep/fail behavior
	 */
	VM_NOSLEEP	= 0x00000000,	/* may fail, won't sleep */
	VM_SLEEP	= 0x00000001,	/* sleep until resource available */
	VM_RECYCLE	= 0x00000002,	/* sleep only for frees to self */
	VM_NOFAIL	= 0x00000004,	/* succeed or abort process */

	/*
	 * Properties
	 */
	VM_VIRTUAL	= 0x00000100,	/* not load/store memory */
	VM_LIMITED	= 0x00000200,	/* limited resource; advisory */
	VM_RESERVED	= 0x00000400,	/* cannot use for vmem metadata */
	VM_NOCACHE	= 0x00000800,	/* do not insert magazine layer */
	VM_NOBULK	= 0x00001000,	/* do not perform bulk imports */
	VM_REALIZES	= 0x00002000,	/* produces load/store memory */
	VM_THREAD	= 0x00004000,	/* single-threaded use; no locking */
	VM_PREALLOC	= 0x00008000,	/* preallocate and map backing memory */

	/*
	 * Debug control
	 */
	VM_DEBUG	= 0x00010000,	/* always do debugging */
	VM_NODEBUG	= 0x00020000,	/* never do debugging */
	VM_MINDEBUG	= 0x00040000,	/* do *at most* minimal debugging */

	/*
	 * Internal
	 */
	VM_NORETRY	= 0x10000000,	/* prevents recursion */
	VM_DYNALLOC     = 0x20000000,   /* vmem itself was dynamically allocd */

} vmem_flag_t;

typedef enum vmem_walk {
	VMEM_WALK_ALLOC	= 0x00000001,	/* walk allocated segments */
	VMEM_WALK_FREE	= 0x00000002,	/* walk free segments */
	VMEM_WALK_DEBUG	= 0x10000000,	/* internal: set arg = vmem_debug_t */
	VMEM_WALK_LOCK	= 0x20000000,	/* internal: walk is already locked */
	VMEM_WALK_PRE	= 0x40000000,	/* internal: walk users in pre-order */
	VMEM_WALK_POST	= 0x80000000,	/* internal: walk users in post-order */
} vmem_walk_t;

typedef enum vmem_vacate {
	VMEM_VACATE_BASE		= 0x01,	/* vacate base allocations */
	VMEM_VACATE_CACHE		= 0x02,	/* vacate cache contents */
	VMEM_VACATE_CACHE_DISABLE	= 0x04,	/* disable and vacate cache */
	VMEM_VACATE_CACHE_ENABLE	= 0x08,	/* enable cache */
	VMEM_VACATE_SELF_ONLY		= 0x10,	/* non-recusrive */
	VMEM_VACATE_ALL = VMEM_VACATE_BASE | VMEM_VACATE_CACHE
} vmem_vacate_t;

typedef struct vmem vmem_t;
typedef struct vmem_ops vmem_ops_t;

typedef void *vmem_alloc_f(vmem_t *, size_t, int);
typedef void *vmem_xalloc_f(vmem_t *, size_t, size_t, size_t, int);
typedef void *vmem_claim_f(vmem_t *, void *, size_t, int);
typedef void vmem_free_f(vmem_t *, void *, size_t);

typedef void *vmem_construct_f(const vmem_t *, void *, size_t, int);
typedef void vmem_destruct_f(const vmem_t *, void *, size_t);
typedef int vmem_sleep_f(vmem_t *, pthread_cond_t *, pthread_mutex_t *);
typedef int vmem_wakeup_f(vmem_t *, pthread_cond_t *);

typedef void vmem_walk_cb(vmem_t *, void *, size_t, void *);

extern vmem_t *vmem_pages[UNUMA_MAX_NODES][UNUMA_PGT_MAX];
extern vmem_t *vmem_heaps[UNUMA_MAX_NODES];
extern vmem_t *vmem_page;  /* deprecated: use vmem_pages instead */
extern vmem_t *vmem_heap;  /* deprecated: use vmem_heaps instead */
extern vmem_t vmem_root;
extern char vmem_panicstr[];
extern char vmem_printf_log[];

extern int vmem_max_cpus;
extern bool vmem_quick_exit;

extern const vmem_ops_t vmem_object_ops;
extern const vmem_ops_t vmem_variable_ops;
extern const vmem_ops_t vmem_heap_ops;

extern const vmem_ops_t vmem_verbose_ops;

extern vmem_t *vmem_create(const vmem_ops_t *, size_t, size_t,
    vmem_t *, vmem_construct_f *, vmem_destruct_f *, int,
    const char *, ...) __attribute__((format(printf, 8, 9)));
extern void vmem_destroy(vmem_t *);
extern vmem_t *vmem_push(vmem_t *, const vmem_ops_t *);
extern vmem_t *vmem_pop(vmem_t *);
extern void *vmem_alloc(vmem_t *, size_t, int);
extern void *vmem_zalloc(vmem_t *, size_t, int);
extern void *vmem_xalloc(vmem_t *, size_t, size_t, size_t, int);
extern void *vmem_claim(vmem_t *, void *, size_t, int);
extern void vmem_free(vmem_t *, void *, size_t);
extern void vmem_add(vmem_t *, void *, size_t);
extern void vmem_remove(vmem_t *, void *, size_t);
extern size_t vmem_walk(vmem_t *, vmem_walk_cb *, void *, int);
extern void vmem_vacate(vmem_t *, int);

extern char *vmem_strdup(vmem_t *, const char *, int);
extern int vmem_sprintf(vmem_t *, int, char **, const char *, ...)
    __attribute__((format(printf, 4, 5)));
extern int vmem_vsprintf(vmem_t *, int, char **, const char *, va_list)
    __attribute__((format(printf, 4, 0)));
extern void vmem_strfree(vmem_t *, char *);

extern const char *vmem_name(const vmem_t *) __attribute__((pure));
extern size_t vmem_align(const vmem_t *) __attribute__((pure));
extern size_t vmem_object(const vmem_t *) __attribute__((pure));
extern size_t vmem_cache_min(void) __attribute__((pure));
extern int vmem_get_numa(const vmem_t *, int *, unuma_pgt_t *);

extern void vmem_setprivate(vmem_t *, void *);
extern void *vmem_getprivate(const vmem_t *);
extern pthread_cond_t *vmem_setsleep(vmem_t *, vmem_sleep_f *, vmem_wakeup_f *);

extern void *vmem_libc_malloc(size_t);
extern void *vmem_libc_calloc(size_t, size_t);
extern void *vmem_libc_memalign(size_t, size_t);
extern void *vmem_libc_valloc(size_t);
extern void *vmem_libc_realloc(void *, size_t);
extern void vmem_libc_free(void *);

#ifdef	__cplusplus
}
#endif

#endif	/* _VMEM_H */
