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
 * Construct/destruct operations
 * ============================================================================
 */
static void *
vmem_cd_default_construct(const vmem_t *vm, void *addr, size_t size, int flag)
{
	return (addr);
}

static void
vmem_cd_default_destruct(const vmem_t *vm, void *addr, size_t size)
{
}

static void *
vmem_cd_xalloc(vmem_t *vm, size_t size, size_t align, size_t phase, int flag)
{
	void *addr;

	addr = vmem_xalloc(vm->vm_source, size, align, phase, flag);

	if (addr == NULL)
		return (NULL);

	if (vm->vm_construct(vm->vm_source, addr, size, flag) == NULL) {
		vmem_free(vm->vm_source, addr, size);
		return (NULL);
	}

	return (addr);
}

static void
vmem_cd_free(vmem_t *vm, void *addr, size_t size)
{
	if (addr == NULL)
		return;

	vm->vm_destruct(vm->vm_source, addr, size);

	vmem_free(vm->vm_source, addr, size);
}

static void
vmem_cd_add(vmem_t *vm, void *addr, size_t size)
{
	vmem_add(vm->vm_source, addr, size);
}

static void
vmem_cd_remove(vmem_t *vm, void *addr, size_t size)
{
	vmem_remove(vm->vm_source, addr, size);
}

static size_t
vmem_cd_walk(vmem_t *vm, vmem_walk_cb *func, void *arg, int w)
{
	return (vmem_walk(vm->vm_source, func, arg, w));
}

static void
vmem_cd_vacate(vmem_t *vm, int v)
{
	if (v & VMEM_VACATE_SELF_ONLY)
		return;

	vmem_vacate(vm->vm_source, v);
}

static int
vmem_cd_init(vmem_t *vm)
{
	if (vm->vm_construct == NULL)
		vm->vm_construct = vmem_cd_default_construct;

	if (vm->vm_destruct == NULL)
		vm->vm_destruct = vmem_cd_default_destruct;

	return (0);
}

static void
vmem_cd_fini(vmem_t *vm)
{
}

const vmem_ops_t vmem_cd_ops = {
	.vop_xalloc = vmem_cd_xalloc,
	.vop_free = vmem_cd_free,
	.vop_debug = NULL,
	.vop_add = vmem_cd_add,
	.vop_remove = vmem_cd_remove,
	.vop_walk = vmem_cd_walk,
	.vop_vacate = vmem_cd_vacate,
	.vop_init = vmem_cd_init,
	.vop_fini = vmem_cd_fini,
	.vop_name = "cd",
	.vop_attr = VMEM_OP_FILTER
};
