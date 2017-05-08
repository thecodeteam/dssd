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
 * Object (fixed-size) operations
 * ============================================================================
 */
static int
vmem_object_init(vmem_t *vm)
{
	if (vm->vm_object == 0)
		return (-1);

	vm->vm_ops = vmem_slab_ops;

	if (vm->vm_ops.vop_init(vm) == 0)
		return (0);

	vm->vm_ops = vmem_seg_ops;

	return (vm->vm_ops.vop_init(vm));
}

const vmem_ops_t vmem_object_ops = {
	.vop_init = vmem_object_init,
	.vop_name = "object",
	.vop_attr = VMEM_OP_BASE | VMEM_OP_ALIAS
};
