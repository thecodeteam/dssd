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

/**
 * @fi vmem.c
 * @br Virtual Memory Allocator @bc
 *
 * 1. Introduction
 * ---------------
 *
 * In the beginning, there was the slab allocator:
 *
 * http://en.wikipedia.org/wiki/Slab_allocation
 * www.usenix.org/publications/library/proceedings/bos94/full_papers/bonwick.ps
 *
 * The slab allocator segregates memory into fixed-size object caches.
 * Each object cache is a collections of slabs, and each slab is simply
 * "one or more pages of virtually contiguous memory carved up into
 * equal-size chunks, with a reference count indicating how many of those
 * chunks have been allocated."  Objects managed by the slab allocator can
 * retain state between free and alloc, so that most setup/teardown only occurs
 * upon first alloc / last free by the object cache's constructor/destructor.
 * "Caching is important because the cost of constructing an object can be
 * significantly higher than the cost of allocating memory for it."
 *
 * The slab allocator excels at managing small to medium data structures
 * but has several limitations: it is single-threaded, it cannot not manage
 * large allocations, and it cannot manage resources other than memory.
 * These can be addressed by a providing a per-CPU magazine layer above the
 * slab allocator, and a general-purpose virtual memory allocator below it:
 *
 * http://www.usenix.org/event/usenix01/bonwick.html
 *
 * The resulting magazine/slab/vmem stack is the basis of the old libumem.
 * Libumem is efficient at most things, but it is a mess architecturally:
 * it is really three different allocators, each with its own interface,
 * and no good way to coordinate activity between them.  In particular,
 * libumem hangs when performing SLEEP allocations of a limited resource.
 * Its core vmem algorithm is also pathologically slow at certain tasks
 * that didn't matter at all in Solaris, but arise frequently in Flood.
 *
 * Flood's extensive use of layered vmem arenas, constrained allocations,
 * and management of scarce resources (such as id16) has highlighted
 * all of these limitations, and demands a better solution.
 *
 *
 * 2. Architecture
 * ---------------
 *
 * Libvmem is a modular memory allocator -- think "stacking vnodes" for memory.
 * Each module is simple (50-500 lines of code) and independent of the others.
 * Complex functionality is built by stacking.  For example, a slab allocator
 * with per-CPU caching and run-time debugging is built up internally by saying:
 *
 * 	vm = vmem_create(&vmem_slab_ops, ...);
 * 	vm = vmem_push(vm, &vmem_magazine_ops);
 * 	vm = vmem_push(vm, &vmem_debug_ops);
 *
 * This modular structure is generally invisible to clients of libvmem.
 * A call to vmem_create() specifies the desired attributes, and libvmem
 * builds an appropriate stack to implement them and returns the stack top.
 * vmem_push() and vmem_pop() are visible symbols for the adventuresome,
 * but are not required in normal use.
 *
 * One particularly nice property of the layered vmem architecture is the
 * elimination of 'if' statements from every vmem_alloc() and vmem_free():
 * if debugging is enabled, if there's a magazine layer, if this, if that.
 * The layered approach means that all of these 'ifs' are resolved once by
 * vmem_create(), and are implicit in the resulting stack.  This makes
 * the code both cleaner and faster than libumem.  It is also much smaller:
 * about 3,000 lines for libvmem vs. 10,000 for libumem, primarily because
 * libvmem is able to use itself due to the uniformity of its ops vectors.
 *
 *
 * 3. Modules
 * ----------
 *
 * There are several vmem module types, and several instances of each:
 *
 * Base:  allocates memory in the usual sense
 *
 * 	vmem_mmap_ops -- uses mmap(2) to get pages of memory
 * 	vmem_slab_ops -- uses slabs to allocate fixed-size objects
 * 	vmem_seg_ops -- uses LLRB trees to allocate variable-size segments
 * 	vmem_unuma_ops -- uses libunuma to get pages of memory
 *
 * Filter:  applies a filter to its source
 *
 * 	vmem_magazine_ops -- per-CPU caching
 *	vmem_thread_ops -- per-thread caching
 * 	vmem_debug_ops -- run-time debugging
 * 	vmem_cd_ops -- constructor/destructor
 * 	vmem_verbose_ops -- reports every transaction
 *
 * Alias:  selects an appropriate base
 *
 * 	vmem_object_ops -- selects slab for small memory objects, seg otherwise
 * 	vmem_variable_ops -- selects seg (only choice at present)
 *
 * Mux:  multiplexes over a set of child arenas
 *
 * 	vmem_heap_ops -- provides fast per-CPU caching for a range of sizes
 *
 * Root:  the root of all arenas
 *
 * 	vmem_root_ops -- used internally to iterate over other arenas
 *
 * The only externally visible ops are object, variable, and heap.
 * Calls to vmem_create() must specify one of these three ops vectors.
 *
 *
 * 4. Interface
 * ------------
 *
 * The libvmem interface is similar to the classic vmem interface,
 * with the exception of vmem_create() -- so read that one closely.
 * Each entry point is documented in detail below; here's the summary:
 *
 * Create/destroy:
 *
 *	vm = vmem_create(ops, ...)		create vm arena
 *	vmem_destroy(vm)			destroy vm arena
 *	vm = vmem_push(vm, ops)			push filter, return stack top
 *	vm = vmem_pop(vm)			pop filter, return stack top
 *
 * Alloc/free:
 *
 *	addr = vmem_alloc(vm, size, flag)	allocate size bytes
 *	addr = vmem_xalloc(vm, size, align, phase, flag)  aligned/phased alloc
 *	addr = vmem_claim(vm, addr, size, flag)	allocate specific addr
 *	vmem_free(vm, addr, size)		free previous alloc/xalloc/claim
 *
 * Add/remove allocatable space:
 *
 *	vmem_add(vm, addr, size)		add allocatable space to vm
 *	vmem_remove(vm, addr, size)		remove allocatable space from vm
 *
 * Walk and vacate:
 *
 *	size = vmem_walk(vm, func, arg, w)	func(vm, addr, size, arg) on all
 *	vmem_vacate(vm, v)			vacate cache or entire arena
 *
 *
 * 5. Interface mapping from libumem to libvmem
 * --------------------------------------------
 *
 * The old umem interfaces are gone entirely, replaced by vmem equivalents.
 * The old vmem interfaces are mostly the same, except for vmem_create() and
 * vmem_xalloc(), plus the addition of vmem_claim(), vmem_push(), vmem_pop(),
 * and vmem_vacate().  The following table provides the interface mapping.
 * Interfaces shown in brackets were missing functionality in libumem.
 *
 * 	libumem				libvmem
 *	-------				-------
 *
 *	vmem_create(...)		vmem_create(&vmem_variable_ops, ...)
 *	umem_cache_create(...)		vmem_create(&vmem_object_ops, ...)
 *	[ umem_heap_create(...) ]	vmem_create(&vmem_heap_ops, ...)
 *
 *	vmem_destroy(vm)		vmem_destroy(vm)
 *	umem_cache_destroy(cp)		vmem_destroy(vm)
 *	[ umem_heap_destroy() ]		vmem_destroy(vm)
 *
 *	[ vmem_push() ]			vmem_push(vm, ops)
 *	[ vmem_pop() ]			vmem_pop(vm, ops)
 *
 *	vmem_alloc(vm, size, flg)	vmem_alloc(vm, size, flg)
 *	umem_cache_alloc(cp, flg)	vmem_alloc(vm, size, flg)
 *	umem_alloc(size, flg)		vmem_alloc(vmem_heap, size, flg)
 *
 *	[ vmem_zalloc() ]		vmem_zalloc(vm, size, flg)
 *	[ umem_cache_zalloc() ]		vmem_zalloc(vm, size, flg)
 *	umem_zalloc(size, flg)		vmem_zalloc(vmem_heap, size, flg)
 *
 *	vmem_xalloc(vm, size, align,	vmem_xalloc(vm, size, align, phase, flg)
 *	    phase, nocross,
 *	    NULL, NULL, flg)
 *	umem_alloc_align(size, align)	vmem_xalloc(vm, size, align, 0, flg)
 *
 *	vmem_xalloc(vm, size, align,	vmem_claim(vm, addr, size, flg)
 *	    phase, nocross,
 *	    addr, addr + size, flg)
 *
 *	vmem_free(vm, addr, size)	vmem_free(vm, addr, size)
 *	vmem_xfree(vm, addr, size)	vmem_free(vm, addr, size)
 *	umem_cache_free(cp, addr)	vmem_free(vm, addr, size)
 * 	umem_free(addr, size)		vmem_free(vmem_heap, addr, size)
 * 	umem_free_align(addr, size)	vmem_free(vmem_heap, addr, size)
 *
 *	vmem_add(vm, addr, size, flg)	vmem_add(vm, addr, size)
 *	[ vmem_remove() ]		vmem_remove(vm, addr, size)
 *
 *	vmem_walk(vm, w, func, arg)	vmem_walk(vm, func, arg, w)
 *	[ umem_cache_walk() ]		vmem_walk(vm, func, arg, w)
 *	umem_cache_applyall()		vmem_walk(&vmem_root, func, arg, w)
 *
 *	vmem_reap()			vmem_vacate(vm, VMEM_VACATE_CACHE)
 *	umem_reap()			vmem_vacate(vm, VMEM_VACATE_CACHE)
 *	[ vmem_vacate() ]		vmem_vacate(vm, VMEM_VACATE_ALL)
 *	[ umem_cache_vacate() ]		vmem_vacate(vm, VMEM_VACATE_ALL)
 *
 *	umem_strdup(s, flg)		vmem_strdup(vmem_heap, s, flg)
 *	umem_strfree(s)			vmem_strfree(vmem_heap, s)
 *
 *	VM_SLEEP			VM_SLEEP
 *	[ UMEM_SLEEP ]			VM_SLEEP
 *
 *	VM_NOSLEEP			VM_NOSLEEP
 *	UMEM_DEFAULT			VM_NOSLEEP
 *
 *	VM_PANIC			VM_NOFAIL
 *	UMEM_NOFAIL			VM_NOFAIL
 *
 *	VMC_IDENTIFIER			VM_VIRTUAL
 *	UMC_NOTOUCH			VM_VIRTUAL
 *
 *	UMC_NODEBUG			VM_NODEBUG
 *	UMF_{AUFIT,DEADBEEF,...}	VM_DEBUG
 *	[ UMF_MINDEBUG ]		VM_MINDEBUG
 *
 *	UMC_NOMAGAZINE			VM_NOCACHE
 *
 * @ec
 */

#include <vmem_impl.h>

static vmem_t *vmem_unuma[UNUMA_MAX_NODES][UNUMA_PGT_MAX];
static vmem_t *vmem_mpage[UNUMA_MAX_NODES][UNUMA_PGT_MAX]; /* multiple pages */
static vmem_t *vmem_selves[UNUMA_MAX_NODES];  /* internal allocations */
vmem_t *vmem_pages[UNUMA_MAX_NODES][UNUMA_PGT_MAX];  /* individual pages */
vmem_t *vmem_heaps[UNUMA_MAX_NODES];  /* heap allocations */
static unuma_pgt_t self_pgt = UNUMA_PGT_SMALL;  /* 'self' alloc page type */

static vmem_t *vmem_large;  /* deprecated large variable arena */
static vmem_t vmem_mmap;
static vmem_t *vmem_self = &vmem_mmap;
vmem_t *vmem_page;
vmem_t *vmem_heap;
vmem_t vmem_root;

size_t vmem_pagesize;
int vmem_max_cpus;
uint64_t vmem_born;
bool vmem_quick_exit;

static size_t vmem_vmemsize;

static int
vmem_sleep(vmem_t *vm, pthread_cond_t *cv, pthread_mutex_t *lp)
{
	return (pthread_cond_wait(cv, lp));
}

static int
vmem_wakeup(vmem_t *vm, pthread_cond_t *cv)
{
	return (pthread_cond_broadcast(cv));
}

/*
 * Find the vmem numa attributes (libunuma node and page type) for the vmem
 * passed.  Returns 0 on success, -1 on failure.  node and pgt are unmodified
 * on failure.
 */
int
vmem_get_numa(const vmem_t *vm, int *node, unuma_pgt_t *pgt)
{
	int nnodes = unuma_get_nnodes();

	if (vm == NULL || vm->vm_origin == NULL)
		return (-1);

	for (int n = 0; n < nnodes; n++)
		for (unuma_pgt_t t = 0; t < UNUMA_PGT_MAX; t++)
			if (vmem_unuma[n][t] == vm->vm_origin) {
				if (node != NULL)
					*node = n;

				if (pgt != NULL)
					*pgt = t;

				return (0);
			}

	return (-1);
}

/*
 * Find the best arena for internal ('self') allocations, based on the arena
 * passed.  The aim is to maximize node locality, i.e. allocate from the same
 * node as the passed arena's origin.
 */
vmem_t *
vmem_find_self(const vmem_t *vm)
{
	int node;

	/*
	 * Find the node that this allocation came from.  Success means that
	 * this vmem was allocated via vmem_unuma, so the unuma vmem_selves
	 * must be used.
	 */
	if (vmem_get_numa(vm, &node, NULL) == 0)
		return (vmem_selves[node]);

	/* This is a legacy allocation (from vmem_self) */
	return (vmem_self);
}

/* Initialize a vmem arena */
static vmem_t *
vmem_init_vm(vmem_t *vm, const vmem_ops_t *ops, size_t q, size_t object,
    vmem_t *source, vmem_construct_f *construct, vmem_destruct_f *destruct,
    int flag, const char *name)
{
	(void) snprintf(vm->vm_name, sizeof (vm->vm_name), "%s", name);

	if (q == 0 || !IS_P2(q) || !IS_P2ALIGNED(object, q)) {
		vmem_panic("vmem_create(ops %p (%s), q %#zx, object %#zx, "
		    "source %p, construct %p, destruct %p, flag %x, '%s'): "
		    "misaligned arguments",
		    ops, ops->vop_name, q, object,
		    source, construct, destruct, flag, vm->vm_name);
	}

	if (source != NULL && (flag & VM_VIRTUAL) == 0 &&
	    (source->vm_flag & (VM_VIRTUAL | VM_REALIZES)) == VM_VIRTUAL)
		vmem_panic("non-VM_VIRTUAL '%s' using VM_VIRTUAL source '%s'\n",
		    vm->vm_name, source->vm_name);

	(void) pthread_mutex_init(&vm->vm_lock, NULL);
	(void) pthread_cond_init(&vm->vm_cv, NULL);

	vm->vm_q = q;
	vm->vm_object = object;
	vm->vm_qshift = ffsl(q) - 1;
	vm->vm_debug = 0;
	vm->vm_source = source;
	vm->vm_base = (ops->vop_attr & VMEM_OP_BASE) ? vm : source->vm_base;
	vm->vm_origin = source ? source->vm_origin : vm;
	vm->vm_construct = construct;
	vm->vm_destruct = destruct;
	vm->vm_flag = flag;
	vm->vm_depth = source ? source->vm_depth + 1 : 0;

	if (vm == vm->vm_base)
		vmem_debug_parse(vm);

	vm->vm_ops = *ops;
	vm->vm_sleep = vmem_sleep;
	vm->vm_wakeup = vmem_wakeup;

	if (ops->vop_init(vm) != 0)
		vmem_panic("cannot initialize vm %p", vm);

	vmem_add(&vmem_root, vm, vmem_vmemsize);

	if (!(vm->vm_ops.vop_attr & (VMEM_OP_FILTER | VMEM_OP_MUX))) {

		int debug = vm->vm_debug && vm->vm_ops.vop_debug;
		int cache = (vm->vm_object != 0 && !(vm->vm_flag & VM_NOCACHE));
		int cd = (vm->vm_construct != NULL || vm->vm_destruct != NULL);

		const vmem_ops_t *cache_ops = (vm->vm_flag & VM_THREAD) ?
		    &vmem_thread_ops : &vmem_magazine_ops;

		if (debug && cache)
			vm = vmem_push(vm, cache_ops);
		if (debug)
			vm = vmem_push(vm, &vmem_debug_ops);
		if (cd)
			vm = vmem_push(vm, &vmem_cd_ops);
		if (!debug && cache)
			vm = vmem_push(vm, cache_ops);
	}

	return (vm);
}

/*
 * ============================================================================
 * Public interfaces
 * ============================================================================
 */

/*
 * vm = vmem_create(ops, q, object, source, construct, destruct, flag, fmt, ...)
 *
 * Create a vmem arena using the specified ops:
 *
 *	&vmem_object_ops -- fixed-size objects of size 'object';
 *	    optimal in both space and time
 *
 *	&vmem_variable_ops -- variable-size allocations;
 *	    optimal in space but not in time
 *
 *	&vmem_heap_ops -- multiplexes between object ops for each
 *	    quarter-power-of-two size with q <= size <= object,
 *	    and variable ops for size > object
 *
 * Be thoughtful with ops selection:  choosing poorly won't necessarily fail,
 * but the result won't be as fast or as space-efficient as it could be.
 * For example, variable ops can satisfy fixed-size object allocations,
 * but not as optimally.  As a rule, use object ops whenever possible,
 * and use variable ops only as a source arena for object ops or heap ops.
 * Use variable ops directly (not as an object/heap source) when per-CPU
 * scalability is not critical, or when the primary use of the arena is
 * to satisfy specific vmem_claim()s rather than general vmem_alloc()s.
 *
 * 'q' is the arena's quantum (minimum alignment).
 *
 * 'object' is the object size (for object ops) or the maximum
 * object size (for heap ops).  It should be zero for variable ops.
 *
 * 'source' is the vmem arena to allocate from when vm is empty.
 * For normal memory objects, vmem_page is the appropriate source.
 *
 * 'construct' and 'destruct' are functions to be invoked by a vmem_cd_ops
 * filter arena for every alloc and free that cannot be satisfied by the
 * magazine layer (if present).  (If 'construct' and 'destruct' are NULL,
 * which is common, no vmem_cd_ops arena will be pushed on the stack.)
 *
 * 'construct(vm, addr, size, flag)' performs first-time setup of addr.
 * It should return addr on success, NULL on failure.
 *
 * 'destruct(vm, addr, size)' performs last-time teardown of addr.
 *
 * 'flag' specifies one or more arena properties as described in vmem.h.
 *
 * 'fmt, ...' specifies the name of the arena using a printf format string
 * and variable arguments.
 *
 * The environment variable VMEM_DEBUG controls debugging (see vmem_debug.c),
 * but can be overridden by the VM_DEBUG, VM_NODEBUG, and VM_MINDEBUG flags.
 */
vmem_t *
__attribute__((format(printf, 8, 9)))
vmem_create(const vmem_ops_t *ops, size_t q, size_t object,
    vmem_t *source, vmem_construct_f *construct, vmem_destruct_f *destruct,
    int flag, const char *fmt, ...)
{
	vmem_t *vm;
	va_list va;
	char name[64];

	va_start(va, fmt);
	(void) vsnprintf(name, sizeof (name), fmt, va);
	va_end(va);

	vm = vmem_zalloc(vmem_find_self(source), vmem_vmemsize, VM_SLEEP);
	vm = vmem_init_vm(vm, ops, q, object, source, construct, destruct,
	    flag | VM_DYNALLOC, name);

	return (vm);
}

/*
 * Destroy vm.  If anything was leaked, it will complain at you.
 */
void
vmem_destroy(vmem_t *vm)
{
	while (vm != NULL)
		vm = vmem_pop(vm);
}

/*
 * Push the ops filter onto vm and return the new stack top.
 */
vmem_t *
vmem_push(vmem_t *vm, const vmem_ops_t *ops)
{
	ASSERT(ops->vop_attr & VMEM_OP_FILTER);

	return (vmem_create(ops, vm->vm_q, vm->vm_object, vm,
	    vm->vm_construct, vm->vm_destruct, vm->vm_flag, "%s", vm->vm_name));
}

/*
 * Pop vm from the stack and return the new stack top.
 */
vmem_t *
vmem_pop(vmem_t *vm)
{
	int nnodes = unuma_get_nnodes();
	vmem_t *next;

	if (vm == vm->vm_base) {
		ASSERT(vm->vm_ops.vop_attr & VMEM_OP_BASE);
		next = NULL;

		size_t leaked = vmem_walk(vm, vmem_debug_leak_cb, NULL,
		    VMEM_WALK_ALLOC | VMEM_WALK_DEBUG);
		if (leaked != 0) {
			if (vm->vm_debug)
				vmem_panic("%s (vm=%p): %zu bytes leaked",
				    vm->vm_name, vm, leaked);
			vmem_printf("%s (vm=%p): %zu bytes leaked\n",
			    vm->vm_name, vm, leaked);
		}
		vmem_vacate(vm, VMEM_VACATE_ALL);
	} else {
		ASSERT(vm->vm_ops.vop_attr & VMEM_OP_FILTER);
		next = vm->vm_source;

		vmem_vacate(vm, VMEM_VACATE_CACHE | VMEM_VACATE_SELF_ONLY);
	}

	if (vm == vmem_self)
		vmem_self = &vmem_mmap;
	else {
		for (int node = 0; node < nnodes; node++)
			if (vm == vmem_selves[node]) {
				vmem_selves[node] = vmem_unuma[node][self_pgt];
				break;
			}
	}

	vmem_remove(&vmem_root, vm, vmem_vmemsize);

	vm->vm_ops.vop_fini(vm);

	(void) pthread_mutex_destroy(&vm->vm_lock);
	(void) pthread_cond_destroy(&vm->vm_cv);

	if ((vm->vm_flag & VM_DYNALLOC) != 0)
		vmem_free(vmem_find_self(vm), vm, vmem_vmemsize);

	return (next);
}

/*
 * Allocate 'size' bytes.
 */
void *
__attribute__((optimize("omit-frame-pointer")))
vmem_alloc(vmem_t *vm, size_t size, int flag)
{
	return (vm->vm_ops.vop_xalloc(vm, size, 0, 0, flag));
}

/*
 * Allocate 'size' bytes and bzero() the result.
 */
void *
__attribute__((optimize("omit-frame-pointer")))
vmem_zalloc(vmem_t *vm, size_t size, int flag)
{
	void *addr = vm->vm_ops.vop_xalloc(vm, size, 0, 0, flag);

	if (addr != NULL)
		bzero(addr, size);

	return (addr);
}

/*
 * Allocate 'size' bytes at offset 'phase' from 'align'.
 * The resulting addr will satisfy P2PHASE(addr, align) == phase.
 */
void *
__attribute__((optimize("omit-frame-pointer")))
vmem_xalloc(vmem_t *vm, size_t size, size_t align, size_t phase, int flag)
{
	return (vm->vm_ops.vop_xalloc(vm, size, align, phase, flag));
}

/*
 * Allocate the specific address 'addr'.  This is mathematically equivalent
 * to asking for an align of 2^64 (== 0 mod 2^64) at a phase of 'addr',
 * which is exactly how it's implemented.
 */
void *
vmem_claim(vmem_t *vm, void *addr, size_t size, int flag)
{
	return (vm->vm_ops.vop_xalloc(vm, size, 0, (uintptr_t)addr, flag));
}

/*
 * Free 'addr', which must be from a previous vmem_alloc(), vmem_xalloc(),
 * or vmem_claim() of the same size.
 */
void
__attribute__((optimize("omit-frame-pointer")))
vmem_free(vmem_t *vm, void *addr, size_t size)
{
	vm->vm_ops.vop_free(vm, addr, size);
}

/*
 * Add allocatable space to the arena.
 */
void
vmem_add(vmem_t *vm, void *addr, size_t size)
{
	vm->vm_ops.vop_add(vm, addr, size);
}

/*
 * Remove allocatable space from the arena.
 */
void
vmem_remove(vmem_t *vm, void *addr, size_t size)
{
	vm->vm_ops.vop_remove(vm, addr, size);
}

/*
 * Walk the arena, applying func(vm, addr, size, arg) to each allocated or
 * free address according to the VMEM_WALK_* flags described in vmem.h.
 */
size_t
vmem_walk(vmem_t *vm, vmem_walk_cb *func, void *arg, int w)
{
	return (vm->vm_ops.vop_walk(vm, func, arg, w));
}

/*
 * Vacate cache (i.e. purge the magazine layer) or the entire arena
 * (i.e. free everything that's allocated, typically before destroy)
 * according to the VMEM_VACATE_* flags described in vmem.h.
 */
void
vmem_vacate(vmem_t *vm, int v)
{
	vm->vm_ops.vop_vacate(vm, v);
}

/*
 * strdup() a string using memory from vm.
 */
char *
vmem_strdup(vmem_t *vm, const char *s, int flag)
{
	char *copy = s ? vmem_alloc(vm, strlen(s) + 1, flag) : NULL;

	if (copy != NULL)
		(void) strcpy(copy, s);

	return (copy);
}

int
__attribute__((format(printf, 4, 0)))
vmem_vsprintf(vmem_t *vm, int flag, char **strp, const char *format, va_list ap)
{
	va_list aq;
	int len;

	va_copy(aq, ap);
	len = vsnprintf(NULL, 0, format, aq);
	va_end(aq);

	if (len < 0)
		return (-1);

	*strp = vmem_alloc(vm, (size_t)len + 1, flag);
	if (*strp == NULL)
		return (-1);

	va_copy(aq, ap);
	(void) vsnprintf(*strp, (size_t)len + 1, format, aq);
	va_end(aq);

	return (len);
}

int
__attribute__((format(printf, 4, 5)))
vmem_sprintf(vmem_t *vm, int flag, char **strp, const char *format, ...)
{
	va_list ap;
	int len;

	va_start(ap, format);
	len = vmem_vsprintf(vm, flag, strp, format, ap);
	va_end(ap);

	return (len);
}

/*
 * Free a string that was allocated by vmem_strdup().
 */
void
vmem_strfree(vmem_t *vm, char *s)
{
	if (s != NULL)
		vmem_free(vm, s, strlen(s) + 1);
}

const char *
__attribute__((pure))
vmem_name(const vmem_t *vm)
{
	return (vm->vm_name);
}

size_t
__attribute__((pure))
__attribute__((optimize("omit-frame-pointer")))
vmem_align(const vmem_t *vm)
{
	return (vm->vm_q);
}

size_t
__attribute__((pure))
__attribute__((optimize("omit-frame-pointer")))
vmem_object(const vmem_t *vm)
{
	return (vm->vm_object);
}

size_t
__attribute__((pure))
vmem_cache_min(void)
{
	return (vmem_max_cpus * VMEM_MAG_ROUNDS * 2);
}

void
vmem_setprivate(vmem_t *vm, void *p)
{
	vm->vm_private = p;
}

void *
vmem_getprivate(const vmem_t *vm)
{
	return (vm->vm_private);
}

pthread_cond_t *
vmem_setsleep(vmem_t *vm, vmem_sleep_f *s, vmem_wakeup_f *w)
{
	vmem_t *ovm = vm->vm_base;

	(void) pthread_mutex_lock(&vm->vm_lock);

	ovm->vm_private = vm->vm_private;
	ovm->vm_sleep = s;
	ovm->vm_wakeup = w;

	(void) pthread_mutex_unlock(&vm->vm_lock);

	return (&ovm->vm_cv);
}


/*
 * Initialize the vmem system.
 *
 * XXX: min_mpage_size is the minimum length of each multi-page arena allocation
 * (vmem_mpage and vmem_large.)  heap_pgt is the libunuma page type used for the
 * heaps.
 *
 * These two variables still need to be tuned.  It is likely that heap_pgt will
 * be set to UNUMA_PGT_LARGE in the future, however each libunuma large/huge
 * page allocation requires a temporary file, which could cause problems if
 * large_size is left at 2MiB, i.e. thousands of open files and their
 * corresponding kernel structures.
 *
 * Care must also be taken to support architectures such as ARM, i.e.
 * min_mpage_size should not be indiscriminately set to UNUMA_PGT_LARGE's size
 * since this is 4K/64K on ARM and would result in too many individual mmap
 * allocations.
 *
 * min_mpage_size and max_mpage_size have been tuned to make each vmem_mpage
 * allocation large enough so there are a small number of resulting underlying
 * allocations, but not too large where allocated-but-unused space would be
 * wasted.  In particular, on x86 with large (2MB) pages these bounds ensure
 * that there aren't too many temporary files under hugetlbfs for these mappings
 * (see libunuma) and the unused space in vmem_mpage[*][UNUMA_PGT_LARGE] is
 * minimized.
 */
static void
__attribute__((constructor))
vmem_init(void)
{
	size_t min_mpage_size = 2UL << 20;  /* min 2MiB allocated for mpages */
	size_t max_mpage_size = 64UL << 20; /* max 64MiB allocated for mpages */
	unuma_pgt_t heap_pgt = UNUMA_PGT_SMALL;  /* type to use for the heap */
	int nnodes = unuma_get_nnodes();
	size_t mpage_size;
	char name[64];

	vmem_born = gethrcycles();
	vmem_max_cpus = cpuid_get_num_conf_cpus();
	vmem_pagesize = getpagesize();
	vmem_vmemsize = P2ROUNDUP(offsetof(vmem_t, vm_cpu[vmem_max_cpus]),
	    vmem_pagesize);

	(void) memset(vmem_unuma, 0, sizeof (vmem_unuma));
	(void) memset(vmem_mpage, 0, sizeof (vmem_mpage));
	(void) memset(vmem_pages, 0, sizeof (vmem_pages));
	(void) memset(vmem_heaps, 0, sizeof (vmem_heaps));
	(void) memset(vmem_selves, 0, sizeof (vmem_selves));

	vmem_init_vm(&vmem_root, &vmem_root_ops, vmem_pagesize, 0,
	    NULL, NULL, NULL, VM_NODEBUG | VM_NOCACHE, "vmem_root");

	vmem_init_vm(&vmem_mmap, &vmem_mmap_ops, vmem_pagesize, 0,
	    NULL, NULL, NULL, VM_NODEBUG | VM_NOCACHE, "vmem_mmap");

	/*
	 * Bootstrap the unuma arenas by manually allocating them on the same
	 * node that they'll allocate memory from in order to maximize locality.
	 */
	for (int node = 0; node < nnodes; node++) {
		for (unuma_pgt_t pgt = 0; pgt < UNUMA_PGT_MAX; pgt++) {
			vmem_unuma[node][pgt] = unuma_alloc(NULL, vmem_vmemsize,
			    0, UNUMA_PGT_SMALL, node);

			(void) memset(vmem_unuma[node][pgt], 0, vmem_vmemsize);

			(void) snprintf(name, sizeof (name),
			    "vmem_unuma_n%d_p%u", node, pgt);

			vmem_init_vm(vmem_unuma[node][pgt], &vmem_unuma_ops,
			    unuma_roundup(1, pgt), 0, NULL, NULL, NULL,
			    VM_NODEBUG | VM_NOCACHE, name);
		}
	}

	/*
	 * Resolve the circular dependency on vmem_selves and vmem_mpage by
	 * temporarily pointing vmem_selves at vmem_unuma so that the vmem_mpage
	 * allocations will succeed.
	 */
	for (int node = 0; node < nnodes; node++)
		vmem_selves[node] = vmem_unuma[node][self_pgt];

	/*
	 * Allocate the multi-page (vmem_mpage), single page (vmem_pages), heap,
	 * and self (used to allocate additional internal arenas) allocations.
	 */
	for (int node = 0; node < nnodes; node++) {
		for (unuma_pgt_t pgt = 0; pgt < UNUMA_PGT_MAX; pgt++) {
			/*
			 * The vmem_mpage arena allocates many unuma pages at a
			 * time for efficiency reasons.  Higher-level arenas,
			 * such as vmem_pages, will make smaller allocations
			 * from these.
			 */
			if (pgt + 1 < UNUMA_PGT_MAX)
				mpage_size = unuma_page_size(pgt + 1) / 2;
			else
				mpage_size = unuma_page_size(pgt);

			if (mpage_size < min_mpage_size)
				mpage_size = min_mpage_size;
			else if (mpage_size > max_mpage_size)
				mpage_size = max_mpage_size;

			mpage_size = unuma_roundup(mpage_size, pgt);

			vmem_mpage[node][pgt] = vmem_create(&vmem_variable_ops,
			    mpage_size, 0, vmem_unuma[node][pgt], NULL, NULL,
			    VM_NODEBUG | VM_NOCACHE,
			    "vmem_mpage_n%d_p%d", node, pgt);

			vmem_pages[node][pgt] = vmem_create(&vmem_variable_ops,
			    unuma_page_size(pgt), 0, vmem_mpage[node][pgt],
			    NULL, NULL, 0, "vmem_pages_n%d_p%u", node, pgt);
		}

		vmem_selves[node] = vmem_create(&vmem_variable_ops,
		    unuma_page_size(self_pgt), 0, vmem_mpage[node][self_pgt],
		    NULL, NULL, 0, "vmem_self_n%d", node);

		vmem_heaps[node] = vmem_create(&vmem_heap_ops, 8,
		    4 * unuma_page_size(UNUMA_PGT_SMALL),
		    vmem_pages[node][heap_pgt], NULL, NULL, 0, "vmem_heaps_n%d",
		    node);
	}

	/* legacy vmems */
	vmem_large = vmem_create(&vmem_variable_ops, min_mpage_size, 0,
	    &vmem_mmap, NULL, NULL, 0, "vmem_large");

	vmem_self = vmem_create(&vmem_variable_ops, vmem_pagesize, 0,
	    vmem_large, NULL, NULL, 0, "vmem_self");

	vmem_page = vmem_create(&vmem_variable_ops, vmem_pagesize, 0,
	    vmem_large, NULL, NULL, 0, "vmem_page");

	vmem_heap = vmem_create(&vmem_heap_ops, 8, 4 * vmem_pagesize,
	    vmem_page, NULL, NULL, 0, "vmem_heap");

	(void) pthread_atfork(vmem_root_lock, vmem_root_unlock,
	    vmem_root_unlock);
}

static void
__attribute__((destructor))
vmem_fini(void)
{
	int nnodes = unuma_get_nnodes();

	/*
	 * Both the "fast" and "living" definitions apply here.  vmem resources
	 * are still in use; do not release them.
	 */
	if (vmem_quick_exit)
		return;

	vmem_vacate(&vmem_root, VMEM_VACATE_ALL);
	vmem_destroy(&vmem_root);

	vmem_heap = NULL;
	vmem_page = NULL;
	vmem_self = &vmem_mmap;
	vmem_large = NULL;

	/* Free the manually-allocated vmem_unuma arenas */
	for (int node = 0; node < nnodes; node++)
		for (unuma_pgt_t pgt = 0; pgt < UNUMA_PGT_MAX; pgt++)
			(void) unuma_free(vmem_unuma[node][pgt], vmem_vmemsize);

	(void) memset(vmem_unuma, 0, sizeof (vmem_unuma));
	(void) memset(vmem_mpage, 0, sizeof (vmem_mpage));
	(void) memset(vmem_pages, 0, sizeof (vmem_pages));
	(void) memset(vmem_heaps, 0, sizeof (vmem_heaps));
	(void) memset(vmem_selves, 0, sizeof (vmem_selves));
}
