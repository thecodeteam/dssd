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
 * Sleep/wakeup
 * ============================================================================
 */
static void
vmem_vacate_cb(vmem_t *vm, void *addr, size_t size, void *arg)
{
	/*
	 * We cannot claw back memory from single-threaded arenas,
	 * because only the owning thread is allowed to touch them.
	 */
	if (vm->vm_flag & VM_THREAD)
		return;

	vmem_vacate(vm, (int)(uintptr_t)arg | VMEM_VACATE_SELF_ONLY);
}

static void
vmem_wait_cb(vmem_t *vm, void *addr, size_t size, void *arg)
{
	if (vm == vm->vm_base) {
		(void) pthread_mutex_lock(&vm->vm_lock);
		vm->vm_waiters += (intptr_t)arg;
		(void) pthread_mutex_unlock(&vm->vm_lock);
	}
}

/*
 * Retry a failed allocation, sleeping if necessary until memory is available.
 */
void *
vmem_xalloc_sleep(vmem_t *vm, size_t size, size_t align, size_t phase, int flag)
{
	void *addr;
	vmem_t *ovm;
	size_t wakeups;
	int err;

	if (!(flag & (VM_SLEEP | VM_NOFAIL)))	// no retry necessary
		return (NULL);

	if (flag & VM_NORETRY)			// no retry allowed
		return (NULL);

	flag |= VM_NORETRY;			// prevent recursion

	/*
	 * Normally, we attempt to reclaim memory from every arena that
	 * consumes from the same origin as vm.  If VM_RECYCLE is specified,
	 * we only reclaim from vm itself, so the origin is vm->vm_base;
	 * otherwise it's vm->vm_origin, which is right above the root.
	 */
	ovm = (flag & VM_RECYCLE) ? vm->vm_base : vm->vm_origin;

	/*
	 * Vacate caches in every arena above the origin and try again.
	 */
	(void) vmem_root.vm_ops.vop_walk(ovm, vmem_vacate_cb,
	    (void *)VMEM_VACATE_CACHE, VMEM_WALK_POST);

	addr = vmem_xalloc(vm, size, align, phase, flag);

	if (addr != NULL)
		return (addr);

	if (!(flag & VM_SLEEP))
		vmem_panic_xalloc(vm, size, align, phase, flag,
		    "NOFAIL failed");

	/*
	 * VM_SLEEP is set, so for every arena above the origin,
	 * disable caching and increment waiters.
	 */
	(void) vmem_root.vm_ops.vop_walk(ovm, vmem_vacate_cb,
	    (void *)VMEM_VACATE_CACHE_DISABLE, VMEM_WALK_POST);

	(void) vmem_root.vm_ops.vop_walk(ovm, vmem_wait_cb,
	    (void *)1UL, VMEM_WALK_PRE);

	/*
	 * Now, keep trying until memory shows up.  By default, we will sleep
	 * indefinitely waiting for a free().  If the client has customized
	 * the vm_sleep() callback, sleep can be interrupted when the callback
	 * returns non-zero, at which point a VM_SLEEP allocation will fail.
	 */
	wakeups = -1UL;
	err = 0;

	while (addr == NULL) {
		(void) pthread_mutex_lock(&ovm->vm_lock);
		while (err == 0 && ovm->vm_wakeups == wakeups)
			err = ovm->vm_sleep(ovm, &ovm->vm_cv, &ovm->vm_lock);
		wakeups = ovm->vm_wakeups;
		(void) pthread_mutex_unlock(&ovm->vm_lock);

		if (err != 0)
			break; /* sleep error or interrupted; return NULL */

		addr = vmem_xalloc(vm, size, align, phase, flag);
	}

	/*
	 * For every arena above the origin,
	 * decrement waiters and reenable caching.
	 */
	(void) vmem_root.vm_ops.vop_walk(ovm, vmem_wait_cb,
	    (void *)-1UL, VMEM_WALK_POST);

	(void) vmem_root.vm_ops.vop_walk(ovm, vmem_vacate_cb,
	    (void *)VMEM_VACATE_CACHE_ENABLE, VMEM_WALK_PRE);

	return (addr);
}

/*
 * Notify waiters that memory is available.  This is invoked by vop_free()
 * of each base arena when it notices vm->vm_waiters != 0.  This check
 * can be done without locking because it can only cause false positives
 * (unnecessary wakeups).  It cannot cause false negatives because the
 * memory that was just freed became visible while the lock was held,
 * so any newly-arrived waiters must have already seen that and found it
 * insufficient to satisfy the allocation.
 */
void
vmem_free_wakeup(vmem_t *vm)
{
	for (vmem_t *ovm = vm; ovm != NULL; ovm = ovm->vm_source) {
		ovm = ovm->vm_base;
		(void) pthread_mutex_lock(&ovm->vm_lock);
		if (ovm->vm_waiters) {
			ovm->vm_wakeups++;
			(void) ovm->vm_wakeup(ovm, &ovm->vm_cv);
		}
		(void) pthread_mutex_unlock(&ovm->vm_lock);
	}
}
