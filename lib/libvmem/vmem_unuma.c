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
 * unuma operations
 * ============================================================================
 */

static void *
vmem_unuma_xalloc(vmem_t *vm, size_t size, size_t align, size_t phase, int flag)
{
	int saved_errno = errno;
	unuma_pgt_t pgt;
	void *vaddr;
	int node;

	if (size == 0)
		return (NULL);

	if (!IS_P2ALIGNED(size | align | phase, vm->vm_q) || !IS_P2(align))
		vmem_panic_xalloc(vm, size, align, phase, flag, "bad args");

	/*
	 * Find the node and pgt for the passed vm so the new allocation has the
	 * same attributes.
	 */
	if (vmem_get_numa(vm, &node, &pgt) != 0)
		return (NULL);

	if ((align | phase) == 0)
		align = vm->vm_q;

	vaddr = (phase >= align) ? (void *)(uintptr_t)phase : NULL;
	vaddr = unuma_alloc(vaddr, size, align, pgt, node);

	if (vaddr == MAP_FAILED) {
		errno = saved_errno;
		return (vmem_xalloc_sleep(vm, size, align, phase, flag));
	}

	ASSERT(P2PHASE((uintptr_t)vaddr, align) == phase);

	errno = saved_errno;
	return (vaddr);
}

static void
vmem_unuma_free(vmem_t *vm, void *addr, size_t size)
{
	int saved_errno = errno;

	if (addr == NULL)
		return;

	(void) unuma_free(addr, size);

	if (vm->vm_waiters)
		vmem_free_wakeup(vm);

	errno = saved_errno;
}

static size_t
vmem_unuma_walk(vmem_t *vm, vmem_walk_cb *func, void *arg, int w)
{
	return (0);
}

static void
vmem_unuma_vacate(vmem_t *vm, int v)
{
}

static int
vmem_unuma_init(vmem_t *vm)
{
	return (0);
}

static void
vmem_unuma_fini(vmem_t *vm)
{
}

const vmem_ops_t vmem_unuma_ops = {
	.vop_xalloc = vmem_unuma_xalloc,
	.vop_free = vmem_unuma_free,
	.vop_debug = NULL,
	.vop_add = NULL,
	.vop_remove = NULL,
	.vop_walk = vmem_unuma_walk,
	.vop_vacate = vmem_unuma_vacate,
	.vop_init = vmem_unuma_init,
	.vop_fini = vmem_unuma_fini,
	.vop_name = "unuma",
	.vop_attr = VMEM_OP_BASE
};
