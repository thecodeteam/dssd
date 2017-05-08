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
 * Verbose operations.
 *
 * This filter arena simply reports every operation with vmem_printf().
 * It is provided both as an example of how to write a simple filter,
 * and as an occasionally useful debugging tool.  Verbosity can be
 * added to any arena by saying "vm = vmem_push(vm, &vmem_verbose_ops);".
 * ============================================================================
 */
static void *
vmem_verbose_xalloc(vmem_t *vm, size_t size, size_t align, size_t phase,
    int flag)
{
	void *addr = vmem_xalloc(vm->vm_source, size, align, phase, flag);

	vmem_printf("vmem_xalloc(%s, %#zx, %#zx, %#zx, %#x) = %p\n",
	    vmem_name(vm), size, align, phase, flag, addr);

	return (addr);
}

static void
vmem_verbose_free(vmem_t *vm, void *addr, size_t size)
{
	vmem_printf("vmem_free(%s, %p, %#zx)\n", vmem_name(vm), addr, size);

	vmem_free(vm->vm_source, addr, size);
}

static void
vmem_verbose_add(vmem_t *vm, void *addr, size_t size)
{
	vmem_printf("vmem_add(%s, %p, %#zx)\n", vmem_name(vm), addr, size);

	vmem_add(vm->vm_source, addr, size);
}

static void
vmem_verbose_remove(vmem_t *vm, void *addr, size_t size)
{
	vmem_printf("vmem_remove(%s, %p, %#zx)\n", vmem_name(vm), addr, size);

	vmem_remove(vm->vm_source, addr, size);
}

static size_t
vmem_verbose_walk(vmem_t *vm, vmem_walk_cb *func, void *arg, int w)
{
	size_t size = vmem_walk(vm->vm_source, func, arg, w);

	vmem_printf("vmem_walk(%s, %p, %p, %#x) = %#zx\n",
	    vmem_name(vm), func, arg, w, size);

	return (size);
}

static void
vmem_verbose_vacate(vmem_t *vm, int v)
{
	vmem_printf("vmem_vacate(%s, %#x)\n", vmem_name(vm), v);

	if (v & VMEM_VACATE_SELF_ONLY)
		return;

	vmem_vacate(vm->vm_source, v);
}

static int
vmem_verbose_init(vmem_t *vm)
{
	vmem_printf("vmem_init(%s)\n", vmem_name(vm));

	return (0);
}

static void
vmem_verbose_fini(vmem_t *vm)
{
	vmem_printf("vmem_fini(%s)\n", vmem_name(vm));
}

const vmem_ops_t vmem_verbose_ops = {
	.vop_xalloc = vmem_verbose_xalloc,
	.vop_free = vmem_verbose_free,
	.vop_debug = NULL,
	.vop_add = vmem_verbose_add,
	.vop_remove = vmem_verbose_remove,
	.vop_walk = vmem_verbose_walk,
	.vop_vacate = vmem_verbose_vacate,
	.vop_init = vmem_verbose_init,
	.vop_fini = vmem_verbose_fini,
	.vop_name = "verbose",
	.vop_attr = VMEM_OP_FILTER
};
