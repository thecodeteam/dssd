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
#include <sys/mman.h>

#include <vmem_impl.h>

/*
 * ============================================================================
 * mmap operations
 * ============================================================================
 */
static void *
vmem_mmap_xalloc(vmem_t *vm, size_t size, size_t align, size_t phase, int flag)
{
	int saved_errno = errno;
	void *addr, *vaddr, *addr_end, *vaddr_end;
	size_t vsize;

	if (size == 0)
		return (NULL);

	if (!IS_P2ALIGNED(size | align | phase, vm->vm_q) || !IS_P2(align))
		vmem_panic_xalloc(vm, size, align, phase, flag, "bad args");

	if ((align | phase) == 0)
		align = vm->vm_q;

	vsize = (align <= vm->vm_q) ? size : P2ROUNDUP(size + align, align);
	vaddr = (phase >= align) ? (void *)(uintptr_t)phase : NULL;
	vaddr = mmap(vaddr, vsize, PROT_READ | PROT_WRITE,
	    MAP_PRIVATE | MAP_ANON | (phase >= align ? MAP_FIXED : 0), -1, 0);
	vaddr_end = vaddr + vsize;

	if (vaddr == MAP_FAILED) {
		errno = saved_errno;
		return (vmem_xalloc_sleep(vm, size, align, phase, flag));
	}

	align = (phase >= align) ? 0 : align;
	addr = (void *)P2PHASEUP((uintptr_t)vaddr, align, phase);
	addr_end = addr + size;
	ASSERT(addr >= vaddr && addr_end <= vaddr_end);
	if (vaddr < addr)
		(void) munmap(vaddr, addr - vaddr);
	if (vaddr_end > addr_end)
		(void) munmap(addr_end, vaddr_end - addr_end);
	ASSERT(P2PHASE((uintptr_t)addr, align) == phase);

	errno = saved_errno;

	return (addr);
}

static void
vmem_mmap_free(vmem_t *vm, void *addr, size_t size)
{
	int saved_errno = errno;

	if (addr == NULL)
		return;

	(void) munmap(addr, P2ROUNDUP(size, vm->vm_q));

	if (vm->vm_waiters)
		vmem_free_wakeup(vm);

	errno = saved_errno;
}

static size_t
vmem_mmap_walk(vmem_t *vm, vmem_walk_cb *func, void *arg, int w)
{
	return (0);
}

static void
vmem_mmap_vacate(vmem_t *vm, int v)
{
}

static int
vmem_mmap_init(vmem_t *vm)
{
	return (0);
}

static void
vmem_mmap_fini(vmem_t *vm)
{
}

const vmem_ops_t vmem_mmap_ops = {
	.vop_xalloc = vmem_mmap_xalloc,
	.vop_free = vmem_mmap_free,
	.vop_debug = NULL,
	.vop_add = NULL,
	.vop_remove = NULL,
	.vop_walk = vmem_mmap_walk,
	.vop_vacate = vmem_mmap_vacate,
	.vop_init = vmem_mmap_init,
	.vop_fini = vmem_mmap_fini,
	.vop_name = "mmap",
	.vop_attr = VMEM_OP_BASE
};
