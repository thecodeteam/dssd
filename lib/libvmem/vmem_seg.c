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

#include <vmem_impl.h>

/*
 * ============================================================================
 * Segment operations
 * ============================================================================
 */
static int
__attribute__((pure))
vmem_seg_addr_compare(const void *a1, const void *a2)
{
	const vmem_seg_t *s1 = a1;
	const vmem_seg_t *s2 = a2;

	if (s1->seg_addr < s2->seg_addr)
		return (-1);
	if (s1->seg_addr > s2->seg_addr)
		return (1);

	return (0);
}

static int
__attribute__((pure))
vmem_seg_size_compare(const void *a1, const void *a2)
{
	const vmem_seg_t *s1 = a1;
	const vmem_seg_t *s2 = a2;

	if (s1->seg_size < s2->seg_size)
		return (-1);
	if (s1->seg_size > s2->seg_size)
		return (1);

	return (vmem_seg_addr_compare(a1, a2));
}

static inline void
vmem_seg_freelist_insert(vmem_t *vm, vmem_seg_t *seg)
{
	seg->seg_addr = vm->vm_seg_freelist;
	vm->vm_seg_freelist = seg;
}

static inline vmem_seg_t *
vmem_seg_freelist_delete(vmem_t *vm)
{
	vmem_seg_t *seg = vm->vm_seg_freelist;

	if (seg != NULL) {
		vm->vm_seg_freelist = seg->seg_addr;
	} else {
		vmem_t *svm = vm->vm_seg_arena;
		(void) pthread_mutex_unlock(&vm->vm_lock);
		seg = vmem_xalloc(svm, svm->vm_object, 0, 0, VM_SLEEP);
		(void) pthread_mutex_lock(&vm->vm_lock);
	}

	return (seg);
}

/*
 * Insert the segment [addr, addr + size) into the arena.
 */
static inline void
vmem_seg_insert(vmem_t *vm, vmem_seg_t *seg, void *addr, size_t size,
    uint8_t seg_free, uint8_t import_start, uint8_t import_end)
{
	ASSERT(IS_P2ALIGNED((uintptr_t)addr, vm->vm_q));

	seg->seg_addr = addr;
	seg->seg_size = size;
	seg->seg_free = seg_free;
	seg->seg_import_start = import_start;
	seg->seg_import_end = import_end;

	tree_insert(&vm->vm_seg_addr_tree, seg);
	if (seg_free)
		tree_insert(&vm->vm_seg_size_tree, seg);

	if (vm->vm_debug)
		vmem_debug_start(vm, addr, size, (void *)(seg + 1));
}

/*
 * Delete seg from the arena.
 */
static inline void
vmem_seg_delete(vmem_t *vm, vmem_seg_t *seg)
{
	tree_delete(&vm->vm_seg_addr_tree, seg);
	if (seg->seg_free)
		tree_delete(&vm->vm_seg_size_tree, seg);
}

/*
 * Import a suitably aligned segment into the arena.
 */
static inline vmem_seg_t *
vmem_seg_import(vmem_t *vm, size_t size, size_t align, size_t phase, int flag)
{
	vmem_t *vm_source = vm->vm_source;
	vmem_seg_t *seg;
	size_t q = vm->vm_q;
	size_t sq = vm_source->vm_q;
	size_t sobj = vm->vm_import_size;
	void *addr;

	if (align == 0)
		align = q;

	size = P2ROUNDUP(phase + size, sq) - P2ALIGN(phase, sq);
	phase = P2ALIGN(phase, sq);
	align = P2ROUNDUP(align, sq);

	if (align == sq)
		align = 0;

	if (sobj && size < sobj)	/* vmem_xalloc checks size > sobj */
		size = sobj;

	(void) pthread_mutex_unlock(&vm->vm_lock);
	addr = vmem_xalloc(vm_source, size, align, phase, flag);
	(void) pthread_mutex_lock(&vm->vm_lock);

	if (addr == NULL)
		return (NULL);

	seg = vmem_seg_freelist_delete(vm);

	vmem_seg_insert(vm, seg, addr, size, 0, 1, 1);

	return (seg);
}

/*
 * Export seg from the arena.
 */
static inline void
vmem_seg_export(vmem_t *vm, vmem_seg_t *seg)
{
	void *addr = seg->seg_addr;
	size_t size = seg->seg_size;

	vmem_seg_delete(vm, seg);
	vmem_seg_freelist_insert(vm, seg);

	(void) pthread_mutex_unlock(&vm->vm_lock);
	vmem_free(vm->vm_source, addr, size);
	(void) pthread_mutex_lock(&vm->vm_lock);
}

/*
 * Find the smallest segment that satisfies the size/align/phase requirements.
 */
static inline vmem_seg_t *
vmem_seg_find_best(vmem_t *vm, size_t size, size_t align, size_t phase)
{
	vmem_seg_t *seg, look;

	look.seg_addr = NULL;
	look.seg_size = size;

	seg = tree_next(&vm->vm_seg_size_tree, &look);

	if (align <= vm->vm_q || seg == NULL ||
	    P2PHASE((uintptr_t)seg->seg_addr, align) == phase)
		return (seg);

	look.seg_size = size + align;
	seg = tree_next(&vm->vm_seg_size_tree, &look);

	return (seg);
}

/*
 * Find the specific segment that contains addr == phase.
 */
static inline vmem_seg_t *
vmem_seg_find_addr(vmem_t *vm, size_t size, size_t align, size_t phase)
{
	vmem_seg_t *seg, *prev, *next, look;
	void *addr, *addr_end, *prev_end;

	ASSERT(phase >= align);

	addr = (void *)phase;
	addr_end = addr + size;

	look.seg_addr = addr;
	look.seg_size = size;

	seg = tree_locate(&vm->vm_seg_addr_tree, &look,
	    (void **)&prev, (void **)&next);

	if (seg != NULL)
		return (seg->seg_free && seg->seg_size >= size ? seg : NULL);

	if (next != NULL && next->seg_addr < addr_end)
		return (NULL);

	if (prev == NULL)
		return (NULL);

	prev_end = prev->seg_addr + prev->seg_size;

	if (prev_end > addr)
		return (prev_end >= addr_end && prev->seg_free ? prev : NULL);

	return (NULL);
}

static void *
vmem_seg_xalloc(vmem_t *vm, size_t size, size_t align, size_t phase, int flag)
{
	vmem_seg_t *seg, *prev, *next;
	void *addr;

	if (size == 0)
		return (NULL);

	if ((vm->vm_object &&
	    (size != vm->vm_object || align > vm->vm_q || phase != 0)) ||
	    (vm->vm_object == 0 &&
	    !IS_P2ALIGNED(size | align | phase, vm->vm_q)) || !IS_P2(align))
		vmem_panic_xalloc(vm, size, align, phase, flag, "bad args");

	if ((align | phase) == 0)
		align = vm->vm_q;

	(void) pthread_mutex_lock(&vm->vm_lock);

	prev = vmem_seg_freelist_delete(vm);
	next = vmem_seg_freelist_delete(vm);

	if (phase < align)
		seg = vmem_seg_find_best(vm, size, align, phase);
	else
		seg = vmem_seg_find_addr(vm, size, align, phase);

	if (seg == NULL && vm->vm_source != NULL)
		seg = vmem_seg_import(vm, size, align, phase,
		    flag | VM_NORETRY);

	if (seg == NULL) {
		vmem_seg_freelist_insert(vm, prev);
		vmem_seg_freelist_insert(vm, next);
		(void) pthread_mutex_unlock(&vm->vm_lock);
		return (vmem_xalloc_sleep(vm, size, align, phase, flag));
	}

	if (seg->seg_free) {
		seg->seg_free = 0;
		tree_delete(&vm->vm_seg_size_tree, seg);
	}

	if (size == seg->seg_size) {
		addr = seg->seg_addr;
	} else {
		align = (phase >= align) ? 0 : align;

		void *seg_addr = seg->seg_addr;
		void *seg_end = seg_addr + seg->seg_size;

		addr = (void *)P2PHASEUP((uintptr_t)seg_addr, align, phase);
		void *addr_end = addr + size;

		ASSERT(seg_addr <= addr && addr_end <= seg_end);

		if (addr_end < seg_end) {
			seg->seg_size = addr_end - seg_addr;
			vmem_seg_insert(vm, next, addr_end, seg_end - addr_end,
			    1, 0, seg->seg_import_end);
			seg->seg_import_end = 0;
			next = NULL;
		}

		if (seg_addr < addr) {
			seg->seg_addr = addr;
			seg->seg_size = addr_end - addr;
			vmem_seg_insert(vm, prev, seg_addr, addr - seg_addr,
			    1, seg->seg_import_start, 0);
			seg->seg_import_start = 0;
			prev = NULL;
		}

		if (vm->vm_debug) {
			vmem_debug_start(vm, addr, size, (void *)(seg + 1));
		}
	}

	if (prev)
		vmem_seg_freelist_insert(vm, prev);
	if (next)
		vmem_seg_freelist_insert(vm, next);

	(void) pthread_mutex_unlock(&vm->vm_lock);

	return (addr);
}

static void
vmem_seg_free(vmem_t *vm, void *addr, size_t size)
{
	vmem_seg_t *seg, *prev, *next, look;

	if (addr == NULL)
		return;

	look.seg_addr = addr;

	(void) pthread_mutex_lock(&vm->vm_lock);

	seg = tree_locate(&vm->vm_seg_addr_tree, &look,
	    (void **)&prev, (void **)&next);

	if (seg == NULL || seg->seg_size != size || seg->seg_free != 0)
		vmem_panic_free(vm, addr, size, "bad free, seg %p", seg);

	/*
	 * Join seg to next and/or prev if they are free, contiguous,
	 * and don't span an import.
	 */
	if (next != NULL && next->seg_free &&
	    seg->seg_addr + seg->seg_size == next->seg_addr &&
	    seg->seg_import_end + next->seg_import_start == 0) {
		seg->seg_size += next->seg_size;
		seg->seg_import_end = next->seg_import_end;
		vmem_seg_delete(vm, next);
	} else {
		next = NULL;
	}

	if (prev != NULL && prev->seg_free &&
	    prev->seg_addr + prev->seg_size == seg->seg_addr &&
	    prev->seg_import_end + seg->seg_import_start == 0) {
		void *prev_addr = prev->seg_addr;
		seg->seg_size += prev->seg_size;
		seg->seg_import_start = prev->seg_import_start;
		vmem_seg_delete(vm, prev);
		seg->seg_addr = prev_addr;
	} else {
		prev = NULL;
	}

	if (vm->vm_debug && seg->seg_size != size)
		vmem_debug_update(vm, seg->seg_addr, seg->seg_size,
		    (void *)(seg + 1));

	if (seg->seg_import_start & seg->seg_import_end) {
		vmem_seg_export(vm, seg);
	} else {
		seg->seg_free = 1;
		tree_insert(&vm->vm_seg_size_tree, seg);
	}

	if (prev)
		vmem_seg_freelist_insert(vm, prev);
	if (next)
		vmem_seg_freelist_insert(vm, next);

	(void) pthread_mutex_unlock(&vm->vm_lock);

	if (vm->vm_waiters)
		vmem_free_wakeup(vm);
}

static vmem_debug_t *
vmem_seg_debug(vmem_t *vm, void *addr, size_t size)
{
	vmem_debug_t *db;
	vmem_seg_t *seg, *prev, *next, look;

	if (addr == NULL && size == 0)
		return (NULL);

	look.seg_addr = addr;

	(void) pthread_mutex_lock(&vm->vm_lock);

	seg = tree_locate(&vm->vm_seg_addr_tree, &look,
	    (void **)&prev, (void **)&next);

	db = vm->vm_dbsize ? (void *)(seg + 1) : NULL;

	if (seg == NULL || seg->seg_size != size || seg->seg_free != 0)
		vmem_panic_free(vm, addr, size,
		    "bad free, seg %p, db %p", seg, db);

	if (next != NULL && next->seg_free &&
	    vm->vm_verify >= sizeof (uint64_t) &&
	    vm->vm_q >= sizeof (uint64_t) &&
	    *(uint64_t *)next->seg_addr != VMEM_DEBUG_FREE)
		vmem_panic_free(vm, addr, size,
		    "redzone violation, seg %p, db %p", seg, db);

	(void) pthread_mutex_unlock(&vm->vm_lock);

	return (db);
}

static void
vmem_seg_add(vmem_t *vm, void *addr, size_t size)
{
	vmem_seg_t *seg;
	vmem_t *svm = vm->vm_seg_arena;

	if (!IS_P2ALIGNED((uintptr_t)addr | size, vm->vm_q) ||
	    addr == NULL || size == 0)
		vmem_panic_free(vm, addr, size, "bad args");

	seg = vmem_xalloc(svm, svm->vm_object, 0, 0, VM_SLEEP);

	(void) pthread_mutex_lock(&vm->vm_lock);
	vmem_seg_insert(vm, seg, addr, size, 0, 0, 0);
	vm->vm_capacity += size;
	(void) pthread_mutex_unlock(&vm->vm_lock);

	vmem_seg_free(vm, addr, size);
}

static void
vmem_seg_remove(vmem_t *vm, void *addr, size_t size)
{
	vmem_seg_t *seg, look;

	if (!IS_P2ALIGNED((uintptr_t)addr | size, vm->vm_q) ||
	    addr == NULL || size == 0)
		vmem_panic_free(vm, addr, size, "bad args");

	(void) vmem_claim(vm, addr, size, VM_SLEEP);

	(void) pthread_mutex_lock(&vm->vm_lock);
	look.seg_addr = addr;
	look.seg_size = size;
	seg = tree_lookup(&vm->vm_seg_addr_tree, &look);
	ASSERT(seg->seg_addr == addr);
	ASSERT(seg->seg_size == size);
	ASSERT(seg->seg_free == 0);
	ASSERT(seg->seg_import_start == 0);
	ASSERT(seg->seg_import_end == 0);
	vmem_seg_delete(vm, seg);
	vmem_seg_freelist_insert(vm, seg);
	vm->vm_capacity -= size;
	(void) pthread_mutex_unlock(&vm->vm_lock);
}

static size_t
vmem_seg_walk(vmem_t *vm, vmem_walk_cb *func, void *arg, int w)
{
	vmem_seg_t *seg, walk = { .seg_addr = NULL };
	size_t wsize = 0;

	(void) pthread_mutex_lock(&vm->vm_lock);

	while ((seg = tree_next(&vm->vm_seg_addr_tree, &walk)) != NULL) {
		walk.seg_addr = seg->seg_addr + seg->seg_size - 1;
		if ((seg->seg_free == 0 && (w & VMEM_WALK_ALLOC)) ||
		    (seg->seg_free == 1 && (w & VMEM_WALK_FREE))) {
			if (w & VMEM_WALK_DEBUG)
				arg = (void *)(seg + 1);
			wsize += seg->seg_size;
			func(vm, seg->seg_addr, seg->seg_size, arg);
		}
	}

	(void) pthread_mutex_unlock(&vm->vm_lock);

	return (wsize);
}

static void
vmem_seg_vacate(vmem_t *vm, int v)
{
	vmem_seg_t *seg, walk = { .seg_addr = NULL };

	if (!(v & VMEM_VACATE_BASE))
		return;

	while ((seg = tree_next(&vm->vm_seg_addr_tree, &walk)) != NULL) {
		walk.seg_addr = seg->seg_addr + seg->seg_size - 1;
		if (!seg->seg_free) {
			vmem_seg_free(vm, seg->seg_addr, seg->seg_size);
		}
	}

	while ((seg = tree_root(&vm->vm_seg_addr_tree)) != NULL) {
		ASSERT(seg->seg_free == 1);
		ASSERT(seg->seg_import_start == 0);
		ASSERT(seg->seg_import_end == 0);
		vmem_seg_delete(vm, seg);
		vmem_seg_freelist_insert(vm, seg);
	}
}

static size_t
vmem_seg_bulk_size(const vmem_t *vm)
{
	const size_t object = vm->vm_object;
	const vmem_t *svm = vm->vm_source;
	size_t sq, size, waste, count, lowsize, lowwaste, lowcount;

	if (svm == NULL)
		return (0);

	/* Must take underlying object size if non-zero. */
	if (svm->vm_object)
		return (svm->vm_object);

	/* Not possible if variable-sized allocator, not allowed if NOBULK. */
	if (object == 0 || vm->vm_flag & VM_NOBULK)
		return (0);

	/* Try 1 to 10 objects or quantums to find the smallest best fit. */
	sq = object > svm->vm_q ? object : svm->vm_q;
	lowsize = lowwaste = P2ROUNDUP(sq, svm->vm_q);
	lowcount = lowsize / object;

	for (int i = 1; i <= 10; i++) {
		size = P2ROUNDUP(sq * i, svm->vm_q);
		count = size / object;
		waste = size % object;

		if (waste * lowcount < lowwaste * count) {
			lowsize = size;
			lowcount = count;
			lowwaste = waste;
		}
	}

	return (lowsize);
}

static int
vmem_seg_init(vmem_t *vm)
{
	/*
	 * Each segment descriptor (vmem_seg_t) has the following format:
	 *
	 *   +--------------------------+---------------+---------------+
	 *   | vmem_seg_t		| debug	& txlog	| prior content	|
	 *   +--------------------------+---------------+---------------+
	 *			^		^		^
	 *			|		|		|
	 *	vmem_seg_t -----+		|		|
	 *	vm_dbsize vmem_debug_t ---------+		|
	 *	vm_content bytes of prior content --------------+
	 *
	 * When no debugging is active, only the vmem_seg_t is allocated.
	 */
	size_t align = __alignof__(vmem_seg_t);
	size_t size = P2ROUNDUP(sizeof (vmem_seg_t) + vm->vm_dbsize +
	    vm->vm_content, align);
	size_t import_size = vmem_seg_bulk_size(vm);

	if (import_size && vm->vm_object > import_size)	/* unsatisfiable */
		return (-1);

	vm->vm_import_size = import_size;
	tree_init(&vm->vm_seg_addr_tree, vmem_seg_addr_compare,
	    offsetof(vmem_seg_t, seg_addr_node));
	tree_init(&vm->vm_seg_size_tree, vmem_seg_size_compare,
	    offsetof(vmem_seg_t, seg_size_node));
	vm->vm_seg_arena = vmem_create(&vmem_slab_ops, align, size,
	    vmem_find_self(vm), NULL, NULL, VM_MINDEBUG | VM_NOCACHE,
	    "%s_vm_seg", vm->vm_name);

	return (0);
}

static void
vmem_seg_fini(vmem_t *vm)
{
	vmem_t *svm = vm->vm_seg_arena;
	size_t size = svm->vm_object;

	while (vm->vm_seg_freelist != NULL) {
		vmem_seg_t *seg = vmem_seg_freelist_delete(vm);
		vmem_free(svm, seg, size);
	}

	tree_fini(&vm->vm_seg_addr_tree);
	tree_fini(&vm->vm_seg_size_tree);
	vmem_destroy(vm->vm_seg_arena);
}

const vmem_ops_t vmem_seg_ops = {
	.vop_xalloc = vmem_seg_xalloc,
	.vop_free = vmem_seg_free,
	.vop_debug = vmem_seg_debug,
	.vop_add = vmem_seg_add,
	.vop_remove = vmem_seg_remove,
	.vop_walk = vmem_seg_walk,
	.vop_vacate = vmem_seg_vacate,
	.vop_init = vmem_seg_init,
	.vop_fini = vmem_seg_fini,
	.vop_name = "seg",
	.vop_attr = VMEM_OP_BASE
};
