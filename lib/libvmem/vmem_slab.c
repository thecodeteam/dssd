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
 * Slab operations
 * ============================================================================
 */
static inline void **
__attribute__((always_inline))
vmem_slab_freelist_link(void *addr, size_t size)
{
	return (addr + size - sizeof (void *));
}

static inline void
__attribute__((always_inline))
vmem_slab_freelist_insert(vmem_slab_t *slab, void *addr, size_t size)
{
	*vmem_slab_freelist_link(addr, size) = slab->slab_freelist;
	slab->slab_freelist = addr;
	slab->slab_used -= size;
}

static inline void *
__attribute__((always_inline))
vmem_slab_freelist_delete(vmem_slab_t *slab, size_t size)
{
	void *addr = slab->slab_freelist;
	slab->slab_freelist = *vmem_slab_freelist_link(addr, size);
	slab->slab_used += size;

	return (addr);
}

static void *
vmem_slab_xalloc(vmem_t *vm, size_t size, size_t align, size_t phase, int flag)
{
	size_t chunk = vm->vm_slab_chunk;
	vmem_slab_t *slab;
	void *addr;

	if (size != vm->vm_object || align > vm->vm_q || phase != 0)
		vmem_panic_xalloc(vm, size, align, phase, flag, "bad args");

	(void) pthread_mutex_lock(&vm->vm_lock);

	slab = list_head(&vm->vm_slab_list);

	if (slab == NULL || slab->slab_freelist == NULL) {
		size_t slab_size = vm->vm_slab_size;
		while ((slab = vm->vm_slab_partial) == NULL) {
			(void) pthread_mutex_unlock(&vm->vm_lock);
			slab = vmem_xalloc(vm->vm_source,
			    slab_size, slab_size, 0, flag | VM_NORETRY);
			(void) pthread_mutex_lock(&vm->vm_lock);
			if (slab == NULL && vm->vm_slab_partial == NULL) {
				(void) pthread_mutex_unlock(&vm->vm_lock);
				return (vmem_xalloc_sleep(vm, size, align,
				    phase, flag));
			}
			if (vm->vm_slab_partial == NULL) {
				size_t space = chunk * vm->vm_slab_chunks;
				slab->slab_freelist = NULL;
				slab->slab_used = space;
				slab->slab_arena = vm;
				list_insert_tail(&vm->vm_slab_list, slab);
				vm->vm_slab_partial = slab;
				vm->vm_slab_partial_offset = slab_size - space;
			} else if (slab != NULL) {
				vmem_free(vm->vm_source, slab, slab_size);
			}
		}
		addr = (void *)slab + vm->vm_slab_partial_offset;
		vm->vm_slab_partial_offset += chunk;
		if (vm->vm_slab_partial_offset == slab_size)
			vm->vm_slab_partial = NULL;
		if (vm->vm_debug)
			vmem_debug_start(vm, addr, vm->vm_object,
			    addr + vm->vm_object);
	} else {
		addr = vmem_slab_freelist_delete(slab, chunk);
	}

	if (slab->slab_freelist == NULL) {
		list_delete(&vm->vm_slab_list, slab);
		list_insert_tail(&vm->vm_slab_list, slab);
	}

	(void) pthread_mutex_unlock(&vm->vm_lock);

	return (addr);
}

static void
vmem_slab_free(vmem_t *vm, void *addr, size_t size)
{
	vmem_slab_t *slab = (void *)P2ALIGN((uintptr_t)addr, vm->vm_slab_size);
	size_t chunk = vm->vm_slab_chunk;

	if (addr == NULL)
		return;

	if (size != vm->vm_object)
		vmem_panic_free(vm, addr, size, "bad size %#zx", size);

	(void) pthread_mutex_lock(&vm->vm_lock);

	if (slab->slab_freelist == NULL) {
		list_delete(&vm->vm_slab_list, slab);
		list_insert_head(&vm->vm_slab_list, slab);
	}

	vmem_slab_freelist_insert(slab, addr, chunk);

	if (slab->slab_used == 0) {
		list_delete(&vm->vm_slab_list, slab);
		(void) pthread_mutex_unlock(&vm->vm_lock);
		vmem_free(vm->vm_source, slab, vm->vm_slab_size);
	} else {
		(void) pthread_mutex_unlock(&vm->vm_lock);
	}

	if (vm->vm_waiters)
		vmem_free_wakeup(vm);
}

static vmem_debug_t *
vmem_slab_debug(vmem_t *vm, void *addr, size_t size)
{
	vmem_debug_t *db = vm->vm_dbsize ? addr + size : NULL;
	vmem_slab_t *slab = (void *)P2ALIGN((uintptr_t)addr, vm->vm_slab_size);

	if (slab->slab_arena != vm)
		vmem_panic_free(vm, addr, size, "wrong arena, db %p", db);

	if (size != vm->vm_object)
		vmem_panic_free(vm, addr, size, "wrong size, db %p", db);

	return (db);
}

static size_t
vmem_slab_walk(vmem_t *vm, vmem_walk_cb *func, void *arg, int w)
{
	vmem_slab_t *slab;
	size_t object = vm->vm_object;
	size_t chunk = vm->vm_slab_chunk;
	size_t chunks = vm->vm_slab_chunks;
	size_t offset = vm->vm_slab_size - chunk * chunks;
	size_t asize = (chunks + 7) / 8;
	size_t c, cmax;
	size_t wsize = 0;
	uint8_t *a = alloca(asize);

	(void) pthread_mutex_lock(&vm->vm_lock);

	for (slab = list_head(&vm->vm_slab_list); slab != NULL;
	    slab = list_next(&vm->vm_slab_list, slab)) {
		void *base = (void *)slab + offset;
		void *addr;

		bzero(a, asize);

		for (addr = slab->slab_freelist; addr != NULL;
		    addr = *vmem_slab_freelist_link(addr, chunk)) {
			c = (size_t)(addr - base) / chunk;
			ASSERT(c < chunks);
			a[c >> 3] |= 1U << (c & 7);
		}

		if (slab == vm->vm_slab_partial)
			cmax = (vm->vm_slab_partial_offset - offset) / chunk;
		else
			cmax = chunks;

		for (c = 0, addr = base; c < cmax; c++, addr += chunk) {
			int is_free = a[c >> 3] & (1U << (c & 7));
			if ((is_free == 0 && (w & VMEM_WALK_ALLOC)) ||
			    (is_free != 0 && (w & VMEM_WALK_FREE))) {
				if (w & VMEM_WALK_DEBUG)
					arg = addr + object;
				wsize += object;
				func(vm, addr, object, arg);
			}
		}
	}

	(void) pthread_mutex_unlock(&vm->vm_lock);

	return (wsize);
}

static void
vmem_slab_vacate(vmem_t *vm, int v)
{
	vmem_slab_t *slab;

	if (!(v & VMEM_VACATE_BASE))
		return;

	while ((slab = list_delete_head(&vm->vm_slab_list)) != NULL)
		vmem_free(vm->vm_source, slab, vm->vm_slab_size);
}

static int
vmem_slab_init(vmem_t *vm)
{
	size_t slab_size, chunk_raw, chunk, schunks, chunks, overhead, capacity;
	vmem_t *svm = vm->vm_source;

	/* Slab prerequisites */
	if (vm->vm_object == 0 ||		// object allocation only
	    vm->vm_q < sizeof (uint64_t) ||	// not sufficiently aligned
	    (vm->vm_flag & VM_VIRTUAL) ||	// not load/store memory
	    (vm->vm_flag & VM_RESERVED))	// can't use space for metadata
		return (-1);

	/* Source prerequisites */
	if (svm == NULL ||				// must have a source
	    (svm->vm_object != 0 && (
	    !IS_P2(svm->vm_object) ||			// wasteful/impossible
	    svm->vm_object > svm->vm_q ||		// "
	    svm->vm_object <= sizeof (vmem_slab_t))))	// not big enough
		return (-1);

	/*
	 * Each slab chunk has the following format:
	 *
	 *   +--------------------------+---------------+---------------+------+
	 *   | object/deadbeef/baddcafe	| debug	& txlog	| prior content	| link |
	 *   +--------------------------+---------------+---------------+------+
	 *			^		^		^	    ^
	 *			|		|		|	    |
	 *	vm_object ------+		|		|	    |
	 *	vm_dbsize vmem_debug_t ---------+		|	    |
	 *	vm_content bytes of prior content --------------+	    |
	 *	sizeof (void *) bytes of slab freelist link ----------------+
	 *
	 * When no debugging is active, only the object itself is allocated,
	 * and the freelist link is stored in the last word of the object.
	 * Either way, the freelist link is always the last word of the chunk.
	 */
	chunk_raw = vm->vm_object + vm->vm_dbsize +
	    vmem_size_min(vm->vm_object, vm->vm_content) +
	    (vm->vm_dbsize || vm->vm_content ? sizeof (void *) : 0);
	chunk = P2ROUNDUP(chunk_raw, vm->vm_q);
	capacity = svm->vm_base->vm_capacity;

	/* Compute ideal size */
	for (slab_size = svm->vm_q; ; slab_size <<= 1) {
		schunks = chunks = (slab_size - sizeof (vmem_slab_t)) / chunk;
		overhead = slab_size - chunk * chunks;

		if (capacity > 0) {
			/*
			 * Add overhead from external fragmentation.
			 * Assumes svm->vm_base->vm_capacity is contiguous.
			 */
			size_t slabs = capacity / slab_size;
			size_t slops = capacity - slabs * slab_size;
			size_t min_slabs = slab_size > svm->vm_q ? 2 : 1;
			if (slabs < min_slabs)
				return (-1);

			chunks *= slabs;
			overhead = overhead * slabs + slops;
		}

		if (slab_size > sizeof (vmem_slab_t) && chunks >= 1) {
			if (overhead <= chunks * VMEM_SIZE_MAX_ABSOVER &&
			    overhead * VMEM_SIZE_MAX_RELOVER <= chunks * chunk)
				break;
			if (vm->vm_flag & VM_NOBULK)
				break;
		}

		if (vm->vm_flag & VM_NOBULK ||	// Told to not bulk import
		    svm->vm_object != 0 ||	// Source can't bulk import
		    chunk >= VMEM_SIZE_WASH)	// Not worth continuing
			return (-1);
	}

	vm->vm_import_size = slab_size;
	list_init(&vm->vm_slab_list, offsetof(vmem_slab_t, slab_node));
	vm->vm_slab_size = slab_size;
	vm->vm_slab_chunk = chunk;
	vm->vm_slab_chunks = schunks;
	vm->vm_slab_partial = NULL;
	vm->vm_slab_partial_offset = 0;

	return (0);
}

static void
vmem_slab_fini(vmem_t *vm)
{
	list_fini(&vm->vm_slab_list);
}

const vmem_ops_t vmem_slab_ops = {
	.vop_xalloc = vmem_slab_xalloc,
	.vop_free = vmem_slab_free,
	.vop_debug = vmem_slab_debug,
	.vop_add = NULL,
	.vop_remove = NULL,
	.vop_walk = vmem_slab_walk,
	.vop_vacate = vmem_slab_vacate,
	.vop_init = vmem_slab_init,
	.vop_fini = vmem_slab_fini,
	.vop_name = "slab",
	.vop_attr = VMEM_OP_BASE
};
