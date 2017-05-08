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
 * Heap operations
 * ============================================================================
 */
static void *
vmem_heap_xalloc(vmem_t *vm, size_t size, size_t align, size_t phase, int flag)
{
	vmem_t *cvm;

	if (!IS_P2(align))
		vmem_panic_xalloc(vm, size, align, phase, flag, "bad args");

	if (align <= vm->vm_q)
		align = 1;

	if ((size - 1) < vm->vm_heap_cache_max) {
		if (P2PHASE(size, align) != 0)
			vmem_panic_xalloc(vm, size, align, phase, flag,
			    "size not aligned");
		if (phase >= align)
			vmem_panic_xalloc(vm, size, align, phase, flag,
			    "address-constrained small heap allocation");
		cvm = vm->vm_heap_cache[(size - 1) >> vm->vm_qshift];
	} else {
		cvm = vm->vm_heap_byte;
	}

	if (align < cvm->vm_q)
		align = cvm->vm_q;

	if (P2PHASE(phase, cvm->vm_q) != 0)
		cvm = vm->vm_heap_byte;

	size = P2ROUNDUP(size, cvm->vm_q);

	return (vmem_xalloc(cvm, size, align, phase, flag));
}

static void
vmem_heap_free(vmem_t *vm, void *addr, size_t size)
{
	vmem_t *cvm;

	if ((size - 1) < vm->vm_heap_cache_max) {
		cvm = vm->vm_heap_cache[(size - 1) >> vm->vm_qshift];
	} else {
		cvm = vm->vm_heap_byte;
	}

	if (P2PHASE((uintptr_t)addr, cvm->vm_q) != 0)
		cvm = vm->vm_heap_byte;

	size = P2ROUNDUP(size, cvm->vm_q);

	vmem_free(cvm, addr, size);
}

static void
vmem_heap_add(vmem_t *vm, void *addr, size_t size)
{
	vmem_add(vm->vm_source, addr, size);
}

static void
vmem_heap_remove(vmem_t *vm, void *addr, size_t size)
{
	vmem_t *cvm;

	for (cvm = list_head(&vm->vm_heap_list); cvm != NULL;
	    cvm = list_next(&vm->vm_heap_list, cvm))
		vmem_vacate(cvm, VMEM_VACATE_CACHE);

	vmem_remove(vm->vm_source, addr, size);
}

static size_t
vmem_heap_walk(vmem_t *vm, vmem_walk_cb *func, void *arg, int w)
{
	vmem_t *cvm;
	size_t wsize = 0;

	for (cvm = list_head(&vm->vm_heap_list); cvm != NULL;
	    cvm = list_next(&vm->vm_heap_list, cvm))
		wsize += vmem_walk(cvm, func, arg, w);

	return (wsize);
}

static void
vmem_heap_vacate(vmem_t *vm, int v)
{
	vmem_t *cvm;

	if (v & VMEM_VACATE_SELF_ONLY)
		return;

	for (cvm = list_head(&vm->vm_heap_list); cvm != NULL;
	    cvm = list_next(&vm->vm_heap_list, cvm))
		vmem_vacate(cvm, v);
}

static int
vmem_heap_init(vmem_t *vm)
{
	vmem_t *svm = vm->vm_source;
	vmem_t *cvm;
	size_t size, align, qsize = 0, s = 0;

	if (vm->vm_object == 0 || svm == NULL)
		return (-1);

	vm->vm_heap_cache_max = vm->vm_object;
	vm->vm_object = 0;

	while (!IS_P2(vm->vm_heap_cache_max))
		vm->vm_heap_cache_max += P2ALIGNOF(vm->vm_heap_cache_max);

	list_init(&vm->vm_heap_list, offsetof(vmem_t, vm_heap_node));

	vm->vm_heap_cache = vmem_alloc(vmem_find_self(vm),
	    P2ROUNDUP(vm->vm_heap_cache_max / vm->vm_q * sizeof (void *),
	    vmem_pagesize), VM_SLEEP);

	for (size = vm->vm_q; size <= vm->vm_heap_cache_max; size += qsize) {
		if (!IS_P2ALIGNED(size, vm->vm_q))
			continue;
		if (IS_P2(size))
			qsize = size >> 2;
		if (qsize == 0)
			qsize = 1;
		align = P2ALIGNOF(size);

		cvm = vmem_create(&vmem_object_ops, align, size, svm,
		    vm->vm_construct, vm->vm_destruct, vm->vm_flag,
		    "%s_%zu", vm->vm_name, size);

		for (; s < size; s += vm->vm_q)
			vm->vm_heap_cache[s >> vm->vm_qshift] = cvm;

		list_insert_tail(&vm->vm_heap_list, cvm);
	}

	vm->vm_heap_byte = vmem_create(&vmem_variable_ops, vm->vm_q, 0, svm,
	    vm->vm_construct, vm->vm_destruct, vm->vm_flag,
	    "%s_byte", vm->vm_name);

	list_insert_tail(&vm->vm_heap_list, vm->vm_heap_byte);

	return (0);
}

static void
vmem_heap_fini(vmem_t *vm)
{
	vmem_t *cvm;

	while ((cvm = list_delete_tail(&vm->vm_heap_list)) != NULL)
		vmem_destroy(cvm);

	vmem_free(vmem_find_self(vm), vm->vm_heap_cache,
	    P2ROUNDUP(vm->vm_heap_cache_max / vm->vm_q * sizeof (void *),
	    vmem_pagesize));

	list_fini(&vm->vm_heap_list);
}

const vmem_ops_t vmem_heap_ops = {
	.vop_xalloc = vmem_heap_xalloc,
	.vop_free = vmem_heap_free,
	.vop_debug = NULL,
	.vop_add = vmem_heap_add,
	.vop_remove = vmem_heap_remove,
	.vop_walk = vmem_heap_walk,
	.vop_vacate = vmem_heap_vacate,
	.vop_init = vmem_heap_init,
	.vop_fini = vmem_heap_fini,
	.vop_name = "heap",
	.vop_attr = VMEM_OP_BASE | VMEM_OP_MUX
};
