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
 * Root operations.
 *
 * The root arena keeps track of all the others.  It maintains vmem_list --
 * a list of all arenas in creation order -- and the vm_users tree, in which
 * each vm's children are its users (i.e. arenas whose vm_source is vm).
 * The root's vm_lock protects both vmem_list and the vm_users tree.
 *
 * vmem_list defines the lock ordering:  when locking all arenas for fork(),
 * we first lock the root (which protects vmem_list), then lock every arena
 * in reverse creation order.  This is also the order in which all arenas
 * are destroyed by vmem_fini(), which issues a vmem_vacate() of vmem_root.
 *
 * vmem_create() adds newly-created arenas to the root using vmem_add(), and
 * vmem_destroy() removes them from the root using vmem_remove().
 *
 * vmem_walk() of the root arena walks the vm_users tree, and can be done
 * in either pre-order or post-order.  It is often useful to walk just the
 * users of a given arena, not of the entire root; this can be done by
 * invoking vmem_root.vm_ops.vop_walk() on that arena.  The implementation
 * of sleep and wakeup -- which reclaim memory recursively from vm_users --
 * takes full advantage of this mechanism.
 * ============================================================================
 */
static list_t vmem_list;

void
vmem_root_lock(void)
{
	vmem_t *vm;

	(void) pthread_mutex_lock(&vmem_root.vm_lock);

	for (vm = list_tail(&vmem_list); vm; vm = list_prev(&vmem_list, vm)) {
		if (vm->vm_mag_arena != NULL) {
			for (int c = 0; c < vmem_max_cpus; c++) {
				vmem_cpu_t *cpu = &vm->vm_cpu[c];
				(void) pthread_mutex_lock(&cpu->cpu_lock);
			}
		}
		(void) pthread_mutex_lock(&vm->vm_lock);
		(void) vm->vm_wakeup(vm, &vm->vm_cv);
	}
}

void
vmem_root_unlock(void)
{
	vmem_t *vm;

	for (vm = list_head(&vmem_list); vm; vm = list_next(&vmem_list, vm)) {
		if (vm->vm_mag_arena != NULL) {
			for (int c = 0; c < vmem_max_cpus; c++) {
				vmem_cpu_t *cpu = &vm->vm_cpu[c];
				(void) pthread_mutex_unlock(&cpu->cpu_lock);
			}
		}
		(void) vm->vm_wakeup(vm, &vm->vm_cv);
		(void) pthread_mutex_unlock(&vm->vm_lock);
	}

	(void) pthread_mutex_unlock(&vmem_root.vm_lock);
}

/*
 * ============================================================================
 * Root ops vector
 * ============================================================================
 */
static void
vmem_root_add(vmem_t *root, void *addr, size_t size)
{
	vmem_t *vm = addr;
	vmem_t *source = vm->vm_source ? vm->vm_source : root;

	if (vm != root) {
		(void) pthread_mutex_lock(&root->vm_lock);
		list_insert_tail(&source->vm_users, vm);
		list_insert_tail(&vmem_list, vm);
		(void) pthread_mutex_unlock(&root->vm_lock);
	}

	list_init(&vm->vm_users, offsetof(vmem_t, vm_user_node));
}

static void
vmem_root_remove(vmem_t *root, void *addr, size_t size)
{
	vmem_t *vm = addr;
	vmem_t *source = vm->vm_source ? vm->vm_source : root;

	list_fini(&vm->vm_users);

	if (vm != root) {
		(void) pthread_mutex_lock(&root->vm_lock);
		list_delete(&source->vm_users, vm);
		list_delete(&vmem_list, vm);
		(void) pthread_mutex_unlock(&root->vm_lock);
	}
}

static size_t
vmem_root_walk(vmem_t *vm, vmem_walk_cb *func, void *arg, int w)
{
	size_t count = 1;
	vmem_t *uvm;

	if (!(w & (VMEM_WALK_PRE | VMEM_WALK_POST)))
		return (0);

	if (!(w & VMEM_WALK_LOCK))
		(void) pthread_mutex_lock(&vmem_root.vm_lock);

	if (w & VMEM_WALK_PRE)
		func(vm, vm, vm->vm_depth, arg);

	for (uvm = list_head(&vm->vm_users); uvm;
	    uvm = list_next(&vm->vm_users, uvm))
		count += vmem_root_walk(uvm, func, arg, w | VMEM_WALK_LOCK);

	if (w & VMEM_WALK_POST)
		func(vm, vm, vm->vm_depth, arg);

	if (!(w & VMEM_WALK_LOCK))
		(void) pthread_mutex_unlock(&vmem_root.vm_lock);

	return (count);
}

static void
vmem_root_vacate(vmem_t *root, int v)
{
	vmem_t *vm;

	if (!(v & VMEM_VACATE_BASE))
		return;

	while ((vm = list_tail(&vmem_list)) != NULL)
		vmem_destroy(vm);
}

static int
vmem_root_init(vmem_t *root)
{
	list_init(&vmem_list, offsetof(vmem_t, vm_list_node));

	return (0);
}

static void
vmem_root_fini(vmem_t *root)
{
	list_fini(&vmem_list);
}

const vmem_ops_t vmem_root_ops = {
	.vop_xalloc = NULL,
	.vop_free = NULL,
	.vop_debug = NULL,
	.vop_add = vmem_root_add,
	.vop_remove = vmem_root_remove,
	.vop_walk = vmem_root_walk,
	.vop_vacate = vmem_root_vacate,
	.vop_init = vmem_root_init,
	.vop_fini = vmem_root_fini,
	.vop_name = "root",
	.vop_attr = VMEM_OP_BASE | VMEM_OP_ROOT
};
