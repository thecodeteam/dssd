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

#ifndef _VMEM_IMPL_H
#define	_VMEM_IMPL_H

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>

#include <pthread.h>

#include <p2.h>
#include <vmem_cpuid.h>
#include <hrtime.h>
#include <list.h>
#include <tree.h>
#include <vmem.h>

#ifdef	__cplusplus
extern "C" {
#endif

typedef struct vmem_slab {
	void *slab_freelist;		/* list of free chunks */
	size_t slab_used;		/* allocated space */
	vmem_t *slab_arena;		/* containing arena */
	list_node_t slab_node;		/* node in arena's list of all slabs */
} vmem_slab_t;

typedef struct vmem_seg {
	void *seg_addr;			/* address of segment */
	size_t seg_size;		/* size of segment */
	uint8_t seg_free;		/* set if seg is free */
	uint8_t seg_import_start;	/* set if addr = start of import */
	uint8_t seg_import_end;		/* set if addr + size = end of import */
	tree_node_t seg_addr_node;	/* node in address-ordered seg tree */
	tree_node_t seg_size_node;	/* node in size-ordered free seg tree */
} __attribute__((aligned(32))) vmem_seg_t;

#define	VMEM_MAG_ROUNDS	(32 - 2)	/* rounds per mag; must be 2^n - 2 */

typedef struct vmem_magazine {
	list_node_t mag_node;		/* depot linkage */
	void *mag_round[VMEM_MAG_ROUNDS]; /* array of free objects */
} vmem_magazine_t;

#define	VMEM_MAG_ALIGN(m)		\
	((void *)P2ALIGN((uintptr_t)(m), sizeof (vmem_magazine_t)))

#define	VMEM_MAG_INVALID(m)					\
	(P2PHASE((uintptr_t)(m), sizeof (vmem_magazine_t)) <	\
	offsetof(vmem_magazine_t, mag_round[0]))

#define	VMEM_MAG_EMPTY(m)		(VMEM_MAG_INVALID(m))
#define	VMEM_MAG_FULL(m)		(VMEM_MAG_INVALID((m) + 1))

typedef struct vmem_cpu {
	pthread_mutex_t cpu_lock;	/* lock for this cpu */
	void **cpu_mag;			/* offset into loaded magazine */
	void **cpu_pmag;		/* offset into previous magazine */
} __attribute__((aligned(64))) vmem_cpu_t;

#define	VMEM_DEBUG_FREE			0xdeadbeefdeadbeefULL
#define	VMEM_DEBUG_ALLOC		0xbaddcafebaddcafeULL
#define	VMEM_DEBUG_REDZONE		0xfeedfacefeedfaceULL

/*
 * Constants for computing acceptable amounts of space overhead for
 * allocations.  Assumes vmem_seg is the always-available, least space-
 * efficient fallback.
 */
#define	VMEM_SIZE_MAX_RELOVER	32	/* inverted: max = size / 32 */
#define	VMEM_SIZE_MAX_ABSOVER	(sizeof (vmem_seg_t))
#define	VMEM_SIZE_WASH		(VMEM_SIZE_MAX_RELOVER * VMEM_SIZE_MAX_ABSOVER)

/*
 * The space overhead of vmem debugging is not always a linear function
 * of the number of stack frames.  Each vmem_debug_t contains 5 fixed words
 * (redzone, addr, size, arena, and state + txid) and, by default,
 * two vmem_tx_t records.  Each vmem_tx_t contains two fixed words
 * (timestamp and thread) in addition to the stack frames.
 * In addition, for anything using slab_ops (the common case),
 * an extra word is needed to store the slab freelist link.
 * Thus the total debug space is:
 *
 *	5 words vmem_debug_t header
 *	2 * (2 + frames) words of vmem_tx_t
 *	1 word of slab freelist linkage
 *
 * With 11 frames, this is 5 + 2 * (2 + 11) + 1 = 32 words = 256 bytes.
 * For 256-byte-aligned objects, adding even one more frame would push the
 * debug cost from 256 bytes to 512 bytes.  We therefore default to 11 frames.
 */
#define	VMEM_TX_STACK	11		/* maximum stack depth per tx */

typedef struct vmem_tx {
	uint64_t tx_timestamp;		/* unscaled time of alloc/free */
	pthread_t tx_thread;		/* thread */
	void *tx_stack[VMEM_TX_STACK];	/* stack trace */
} vmem_tx_t;

typedef struct vmem_debug {
	uint64_t db_redzone;		/* redzone word */
	void *db_addr;			/* address */
	size_t db_size;			/* size */
	vmem_t *db_arena;		/* arena */
	char db_state;			/* 'a' = allocated, 'f' = free */
	int db_txid;			/* transaction ID */
	vmem_tx_t db_tx[2];		/* history of transactions */
} vmem_debug_t;

typedef struct vmem_bt {
	void *bt_vaddr;			/* malloc boundary tag: real addr */
	size_t bt_vsize;		/* malloc boundary tag: real size */
} vmem_bt_t;

typedef vmem_debug_t *vmem_debug_f(vmem_t *, void *, size_t);
typedef void vmem_add_f(vmem_t *, void *, size_t);
typedef void vmem_remove_f(vmem_t *, void *, size_t);
typedef size_t vmem_walk_f(vmem_t *, vmem_walk_cb *, void *, int);
typedef void vmem_vacate_f(vmem_t *, int);
typedef int vmem_init_f(vmem_t *);
typedef void vmem_fini_f(vmem_t *);

typedef enum vmem_op_attr {
	VMEM_OP_ROOT	= 0x01,		/* root (vmem_root) */
	VMEM_OP_BASE	= 0x02,		/* base (slab, seg, mmap, heap, root) */
	VMEM_OP_FILTER	= 0x04,		/* filter (magazine, debug, cd) */
	VMEM_OP_ALIAS	= 0x08,		/* alias (object, variable) */
	VMEM_OP_MUX	= 0x10,		/* mux (heap) */
} vmem_op_attr_t;

struct vmem_ops {
	vmem_xalloc_f *vop_xalloc;	/* allocate (size, align, phase) */
	vmem_free_f *vop_free;		/* free (addr, size) */
	vmem_debug_f *vop_debug;	/* debug_lookup (addr, size, hint) */
	vmem_add_f *vop_add;		/* add (addr, size) to arena */
	vmem_remove_f *vop_remove;	/* remove (addr, size) from arena */
	vmem_walk_f *vop_walk;		/* walk allocated addrs, invoking cb */
	vmem_vacate_f *vop_vacate;	/* vacate caches or entire arena */
	vmem_init_f *vop_init;		/* init(vm): called by vmem_create() */
	vmem_fini_f *vop_fini;		/* fini(vm): called by vmem_destroy() */
	const char *vop_name;		/* operation name */
	vmem_op_attr_t vop_attr;	/* operation attributes */
};

struct vmem {
	__attribute__((aligned(64)))
	char vm_name[64];		/* arena name */

	/*
	 * Hot arena state -- mutex (40 bytes) + 3 words = 64 bytes
	 */
	__attribute__((aligned(64)))
	pthread_mutex_t vm_lock;	/* protects all arena state */
	size_t vm_q;			/* arena's quantum */
	size_t vm_object;		/* object size */
	uint32_t vm_qshift;		/* quantum shift, i.e. log2(vm_q) */
	uint32_t vm_debug;		/* debugging enabled? */

	/*
	 * Cold arena state -- 5 words + 6 ints = 64 bytes
	 */
	__attribute__((aligned(64)))
	vmem_t *vm_source;		/* source arena for import/export */
	vmem_t *vm_base;		/* base arena (slab, seg, mmap) */
	vmem_t *vm_origin;		/* ultimate source; child of root */
	vmem_construct_f *vm_construct;	/* constructor */
	vmem_destruct_f *vm_destruct;	/* destructor */

	int vm_flag;			/* vmem_flag_t creation flags */
	int vm_depth;			/* depth from vmem_root */

	uint32_t vm_tx;			/* debug: slots in transaction ring */
	uint32_t vm_dbsize;		/* debug: size of debug record */
	uint32_t vm_verify;		/* debug: bytes to verify deadbeef */
	uint32_t vm_content;		/* debug: bytes of content to save */

	/*
	 * Sleep state -- cond (48 bytes) + 2 words = 64 bytes
	 */
	__attribute__((aligned(64)))
	pthread_cond_t vm_cv;		/* for VM_SLEEP allocations */
	size_t vm_wakeups;		/* wakeup generation number */
	size_t vm_waiters;		/* threads waiting for wakeup */

	/*
	 * Ops vector and private data -- 128 bytes
	 */
	__attribute__((aligned(64)))
	vmem_ops_t vm_ops;		/* ops vector: slab, seg, heap, etc */
	vmem_sleep_f *vm_sleep;		/* sleep callback (cond_wait) */
	vmem_wakeup_f *vm_wakeup;	/* wakeup callback (cond_broadcast) */
	void *vm_private;		/* caller-maintained private data */
	size_t vm_import_size;		/* preferred source import size */
	size_t vm_capacity;		/* vmem_add()ed capacity */

	/*
	 * Root-owned VSD -- 7 words = 56 bytes
	 */
	__attribute__((aligned(64)))
	list_t vm_users;		/* list of arenas using this one */
	list_node_t vm_user_node;	/* node in list of users */
	list_node_t vm_list_node;	/* node in list of all arenas */

	/*
	 * Slab VSD -- 8 words = 64 bytes
	 */
	__attribute__((aligned(64)))
	list_t vm_slab_list;		/* list of slabs; empty ones at end */
	size_t vm_slab_size;		/* slab size */
	size_t vm_slab_chunk;		/* chunk size */
	size_t vm_slab_chunks;		/* chunks per slab */
	size_t vm_slab_partial_offset;	/* offset into partial slab */
	vmem_slab_t *vm_slab_partial;	/* partially consumed slab */

	/*
	 * Seg VSD -- 8 words = 64 bytes
	 */
	__attribute__((aligned(64)))
	tree_t vm_seg_addr_tree;	/* address-ordered tree of segments */
	tree_t vm_seg_size_tree;	/* size-ordered tree of free segments */
	vmem_t *vm_seg_arena;		/* vmem_seg_t arena */
	vmem_seg_t *vm_seg_freelist;	/* cache of vmem_seg_t structures */

	/*
	 * Heap VSD -- 8 words = 64 bytes
	 */
	__attribute__((aligned(64)))
	size_t vm_heap_cache_max;	/* cached heap allocation limit */
	vmem_t **vm_heap_cache;		/* small-allocation heap caches */
	vmem_t *vm_heap_byte;		/* arbitrary byte-aligned allocations */
	list_t vm_heap_list;		/* sub-arenas (caches and unaligned) */
	list_node_t vm_heap_node;	/* node in vm_heap_list */

	/*
	 * Magazine VSD -- 8 words = 64 bytes
	 */
	__attribute__((aligned(64)))
	vmem_t *vm_mag_arena;		/* vmem_magazine_t arena */
	list_t vm_mag_full;		/* full magazines */
	list_t vm_mag_empty;		/* empty magazines */
	int32_t vm_mag_disabled;	/* magazine disable count */

	/*
	 * Per-CPU magazine VSD -- 64 bytes * number of CPUs
	 */
	vmem_cpu_t vm_cpu[0];		/* per-CPU magazines */
};

#define	ASSERT	assert

static inline size_t
__attribute__((always_inline))
vmem_size_min(size_t a, size_t b)
{
	return (a < b ? a : b);
}

extern const vmem_ops_t vmem_cd_ops;
extern const vmem_ops_t vmem_debug_ops;
extern const vmem_ops_t vmem_magazine_ops;
extern const vmem_ops_t vmem_mmap_ops;
extern const vmem_ops_t vmem_unuma_ops;
extern const vmem_ops_t vmem_root_ops;
extern const vmem_ops_t vmem_seg_ops;
extern const vmem_ops_t vmem_slab_ops;
extern const vmem_ops_t vmem_thread_ops;

extern uint64_t vmem_born;
extern size_t vmem_pagesize;

extern vmem_xalloc_f vmem_xalloc_sleep;
extern void vmem_free_wakeup(vmem_t *);
extern vmem_t *vmem_find_self(const vmem_t *);

extern void vmem_root_lock(void);
extern void vmem_root_unlock(void);

extern void vmem_debug_parse(vmem_t *);
extern void vmem_debug_start(vmem_t *, void *, size_t, vmem_debug_t *);
extern void vmem_debug_update(vmem_t *, void *, size_t, vmem_debug_t *);
extern vmem_walk_cb vmem_debug_leak_cb;

extern void vmem_printf(const char *fmt, ...)
    __attribute__((format(printf, 1, 2)));
extern void vmem_panic(const char *fmt, ...)
    __attribute__((format(printf, 1, 2)))
    __attribute__((noreturn));
extern void vmem_panic_xalloc(vmem_t *, size_t, size_t, size_t, int,
    const char *fmt, ...)
    __attribute__((format(printf, 6, 7)))
    __attribute__((noreturn));
extern void vmem_panic_free(vmem_t *, void *, size_t, const char *fmt, ...)
    __attribute__((format(printf, 4, 5)))
    __attribute__((noreturn));

#ifdef	__cplusplus
}
#endif

#endif	/* _VMEM_IMPL_H */
