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

#include <errno.h>
#include <vmem_impl.h>

/*
 * ============================================================================
 * C library malloc equivalents
 * ============================================================================
 */
static inline void *
vmem_libc_alloc(size_t size, size_t align, int zero)
{
	vmem_bt_t *bt;
	void *addr, *vaddr;
	size_t vsize;
	size_t page = vmem_pagesize;

	if (align < sizeof (*bt))
		align = sizeof (*bt);

	if (align <= vmem_heap->vm_heap_cache_max) {
		vsize = P2ROUNDUP(size, align) + align;
		vaddr = vmem_xalloc(vmem_heap, vsize, 0, 0, VM_NOSLEEP);
		addr = (void *)P2ROUNDUP((uintptr_t)vaddr, align);
		if (addr == vaddr) {
			addr += align;
		}
	} else {
		vsize = P2ROUNDUP(size, align) + page;
		vaddr = vmem_xalloc(vmem_heap, vsize, align, align - page,
		    VM_NOSLEEP);
		addr = vaddr + page;
	}

	if (vaddr == NULL) {
		errno = ENOMEM;
		return (NULL);
	}

	ASSERT(P2PHASE((uintptr_t)addr, align) == 0);
	ASSERT(addr >= vaddr + sizeof (*bt));
	ASSERT(addr + size <= vaddr + vsize);

	bt = addr - sizeof (*bt);
	bt->bt_vaddr = vaddr;
	bt->bt_vsize = vsize;

	if (zero)
		bzero(addr, size);

	return (addr);
}

void
vmem_libc_free(void *addr)
{
	vmem_bt_t *bt = addr - sizeof (*bt);
	void *vaddr;

	if (addr == NULL)
		return;

	vaddr = bt->bt_vaddr;

	if (vaddr == (void *)VMEM_DEBUG_FREE)
		vmem_panic("free(%p): double free, bt %p", addr, bt);

	bt->bt_vaddr = (void *)VMEM_DEBUG_FREE;

	vmem_free(vmem_heap, vaddr, bt->bt_vsize);
}

void *
vmem_libc_malloc(size_t size)
{
	return (vmem_libc_alloc(size, 0, 0));
}

void *
vmem_libc_calloc(size_t count, size_t size)
{
	return (vmem_libc_alloc(size * count, 0, 1));
}

void *
vmem_libc_memalign(size_t align, size_t size)
{
	return (vmem_libc_alloc(size, align, 0));
}

void *
vmem_libc_valloc(size_t size)
{
	return (vmem_libc_alloc(size, vmem_pagesize, 0));
}

void *
vmem_libc_realloc(void *addr, size_t size)
{
	vmem_bt_t *bt = addr - sizeof (*bt);
	void *oldvaddr, *newaddr;
	size_t oldvsize;

	if (addr == NULL)
		return (vmem_libc_alloc(size, 0, 0));

	oldvaddr = bt->bt_vaddr;
	oldvsize = bt->bt_vsize;

	if (oldvaddr == (void *)VMEM_DEBUG_FREE)
		vmem_panic("realloc(%p): addr is free, bt %p", addr, bt);

	if (oldvaddr + oldvsize == addr + P2ROUNDUP(size, sizeof (*bt)))
		return (addr);

	newaddr = vmem_libc_alloc(size, 0, 0);

	if (newaddr == NULL)
		return (NULL);

	bcopy(addr, newaddr, vmem_size_min(oldvaddr + oldvsize - addr, size));
	vmem_libc_free(addr);

	return (newaddr);
}
