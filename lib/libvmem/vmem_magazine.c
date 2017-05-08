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
 * Magazine operations / Thread operations
 *
 * The magazine ops provide fast, linear-scaling, per-CPU alloc/free caching.
 *
 * For VM_THREAD arenas that are only accessed by one thread, single-threaded
 * allocation can be made even faster by using vmem_thread_ops, which is
 * a variant compilation of vmem_magazine_ops with no locks and no cpuid.
 * ============================================================================
 */
#ifdef VMEM_THREAD_OPS

#undef pthread_mutex_lock
#undef pthread_mutex_unlock
#undef cpuid_get_cpu

#define	pthread_mutex_lock(x)	(0)
#define	pthread_mutex_unlock(x)	(0)
#define	cpuid_get_cpu()		(0)

/*
 * These symbol redefinitions are not strictly necessary because all symbols
 * except vmem_xxx_ops are static.  This is done solely to aid debugging.
 */
#define	vmem_magazine_evict	vmem_thread_evict
#define	vmem_magazine_purge	vmem_thread_purge
#define	vmem_magazine_populate	vmem_thread_populate
#define	vmem_magazine_disable	vmem_thread_disable
#define	vmem_magazine_enable	vmem_thread_enable
#define	vmem_magazine_xalloc	vmem_thread_xalloc
#define	vmem_magazine_free	vmem_thread_free
#define	vmem_magazine_add	vmem_thread_add
#define	vmem_magazine_remove	vmem_thread_remove
#define	vmem_magazine_walk	vmem_thread_walk
#define	vmem_magazine_vacate	vmem_thread_vacate
#define	vmem_magazine_init	vmem_thread_init
#define	vmem_magazine_fini	vmem_thread_fini
#define	vmem_magazine_ops	vmem_thread_ops

#endif

static void
vmem_magazine_evict(vmem_t *vm, vmem_magazine_t *m, int rounds)
{
	size_t size = vm->vm_object;

	for (int r = 0; r < rounds; r++)
		vmem_free(vm->vm_source, m->mag_round[r], size);

	vmem_free(vm->vm_mag_arena, m, sizeof (*m));
}

static void
vmem_magazine_purge(vmem_t *vm)
{
	list_t ml[VMEM_MAG_ROUNDS + 1];

	for (int r = 0; r <= VMEM_MAG_ROUNDS; r++)
		list_init(&ml[r], offsetof(vmem_magazine_t, mag_node));

	for (int c = 0; c < vmem_max_cpus; c++)
		(void) pthread_mutex_lock(&vm->vm_cpu[c].cpu_lock);

	(void) pthread_mutex_lock(&vm->vm_lock);

	list_move(&vm->vm_mag_full, &ml[VMEM_MAG_ROUNDS]);
	list_move(&vm->vm_mag_empty, &ml[0]);

	for (int c = 0; c < vmem_max_cpus; c++) {
		vmem_cpu_t *cpu = &vm->vm_cpu[c];
		vmem_magazine_t *mag;
		void **m;
		int r;

		if ((m = cpu->cpu_mag) != NULL) {
			mag = VMEM_MAG_ALIGN(m);
			r = m - &mag->mag_round[-1];
			ASSERT(r >= 0 && r <= VMEM_MAG_ROUNDS);
			list_insert_head(&ml[r], mag);
			cpu->cpu_mag = NULL;
		}
		if ((m = cpu->cpu_pmag) != NULL) {
			mag = VMEM_MAG_ALIGN(m);
			r = m - &mag->mag_round[-1];
			ASSERT(r >= 0 && r <= VMEM_MAG_ROUNDS);
			list_insert_head(&ml[r], mag);
			cpu->cpu_pmag = NULL;
		}
	}

	(void) pthread_mutex_unlock(&vm->vm_lock);

	for (int c = 0; c < vmem_max_cpus; c++)
		(void) pthread_mutex_unlock(&vm->vm_cpu[c].cpu_lock);

	for (int r = 0; r <= VMEM_MAG_ROUNDS; r++) {
		vmem_magazine_t *m;
		while ((m = list_delete_head(&ml[r])) != NULL)
			vmem_magazine_evict(vm, m, r);
		list_fini(&ml[r]);
	}
}

static void
vmem_magazine_populate(vmem_t *vm)
{
	vmem_magazine_t *e;

	if (vm->vm_mag_disabled)	// false positives and negatives OK
		return;

	e = vmem_xalloc(vm->vm_mag_arena, sizeof (*e), 0, 0, VM_NOSLEEP);

	(void) pthread_mutex_lock(&vm->vm_lock);
	if (e != NULL && vm->vm_mag_disabled == 0) {
		list_insert_head(&vm->vm_mag_empty, e);
		e = NULL;
	}
	(void) pthread_mutex_unlock(&vm->vm_lock);

	if (e != NULL)
		vmem_free(vm->vm_mag_arena, e, sizeof (*e));
}

static void
vmem_magazine_disable(vmem_t *vm)
{
	(void) pthread_mutex_lock(&vm->vm_lock);
	vm->vm_mag_disabled++;
	(void) pthread_mutex_unlock(&vm->vm_lock);

	vmem_magazine_purge(vm);
}

static void
vmem_magazine_enable(vmem_t *vm)
{
	(void) pthread_mutex_lock(&vm->vm_lock);
	ASSERT(vm->vm_mag_disabled > 0);
	vm->vm_mag_disabled--;
	(void) pthread_mutex_unlock(&vm->vm_lock);
}

static void *
vmem_magazine_xalloc(vmem_t *vm, size_t size, size_t align, size_t phase,
    int flag)
{
	vmem_cpu_t *cpu = &vm->vm_cpu[cpuid_get_cpu()];
	vmem_magazine_t *f;
	void **m, **p, **n, *addr;

	if (size != vm->vm_object || align > vm->vm_q || phase != 0)
		vmem_panic_xalloc(vm, size, align, phase, flag, "bad args");

	(void) pthread_mutex_lock(&cpu->cpu_lock);
	m = cpu->cpu_mag;
	if (VMEM_MAG_EMPTY(m)) {
		p = cpu->cpu_pmag;
		if (VMEM_MAG_EMPTY(p)) {
			(void) pthread_mutex_lock(&vm->vm_lock);
			f = list_delete_head(&vm->vm_mag_full);
			if (f == NULL) {
				(void) pthread_mutex_unlock(&vm->vm_lock);
				(void) pthread_mutex_unlock(&cpu->cpu_lock);
				return (vmem_xalloc(vm->vm_source,
				    size, align, phase, flag));
			}
			if (p != NULL) {
				list_insert_head(&vm->vm_mag_empty,
				    VMEM_MAG_ALIGN(p));
			}
			(void) pthread_mutex_unlock(&vm->vm_lock);
			n = &f->mag_round[VMEM_MAG_ROUNDS - 1];
		} else {
			n = p;
		}
		cpu->cpu_pmag = m;
		cpu->cpu_mag = m = n;
	}
	addr = *m;
	cpu->cpu_mag = --m;
	(void) pthread_mutex_unlock(&cpu->cpu_lock);

	return (addr);
}

static void
vmem_magazine_free(vmem_t *vm, void *addr, size_t size)
{
	vmem_cpu_t *cpu = &vm->vm_cpu[cpuid_get_cpu()];
	vmem_magazine_t *e;
	void **m, **p, **n;

	if (addr == NULL)
		return;

	if (size != vm->vm_object)
		vmem_panic_free(vm, addr, size, "bad args");

	(void) pthread_mutex_lock(&cpu->cpu_lock);
	m = cpu->cpu_mag;
	if (VMEM_MAG_FULL(m)) {
		p = cpu->cpu_pmag;
		if (VMEM_MAG_FULL(p)) {
			(void) pthread_mutex_lock(&vm->vm_lock);
			e = list_delete_head(&vm->vm_mag_empty);
			if (e == NULL) {
				(void) pthread_mutex_unlock(&vm->vm_lock);
				(void) pthread_mutex_unlock(&cpu->cpu_lock);
				vmem_magazine_populate(vm);
				vmem_free(vm->vm_source, addr, size);
				return;
			}
			if (p != NULL) {
				list_insert_head(&vm->vm_mag_full,
				    VMEM_MAG_ALIGN(p));
			}
			(void) pthread_mutex_unlock(&vm->vm_lock);
			n = &e->mag_round[-1];
		} else {
			n = p;
		}
		cpu->cpu_pmag = m;
		cpu->cpu_mag = m = n;
	}
	cpu->cpu_mag = ++m;
	*m = addr;
	(void) pthread_mutex_unlock(&cpu->cpu_lock);
}

static void
vmem_magazine_add(vmem_t *vm, void *addr, size_t size)
{
	vmem_add(vm->vm_source, addr, size);
}

static void
vmem_magazine_remove(vmem_t *vm, void *addr, size_t size)
{
	vmem_magazine_purge(vm);
	vmem_remove(vm->vm_source, addr, size);
}

static size_t
vmem_magazine_walk(vmem_t *vm, vmem_walk_cb *func, void *arg, int w)
{
	size_t size;

	vmem_magazine_disable(vm);
	size = vmem_walk(vm->vm_source, func, arg, w);
	vmem_magazine_enable(vm);

	return (size);
}

static void
vmem_magazine_vacate(vmem_t *vm, int v)
{
	if (v & VMEM_VACATE_CACHE)
		vmem_magazine_purge(vm);

	if (v & VMEM_VACATE_CACHE_DISABLE)
		vmem_magazine_disable(vm);

	if (v & VMEM_VACATE_CACHE_ENABLE)
		vmem_magazine_enable(vm);

	if (v & VMEM_VACATE_SELF_ONLY)
		return;

	vmem_vacate(vm->vm_source, v);
}

static int
vmem_magazine_init(vmem_t *vm)
{
	if (vm->vm_object == 0)
		return (-1);

	vm->vm_mag_arena = vmem_create(&vmem_slab_ops,
	    sizeof (vmem_magazine_t), sizeof (vmem_magazine_t),
	    vmem_find_self(vm), NULL, NULL,
	    VM_NOBULK | VM_MINDEBUG | VM_NOCACHE, "%s_vm_mag", vm->vm_name);

	list_init(&vm->vm_mag_full, offsetof(vmem_magazine_t, mag_node));
	list_init(&vm->vm_mag_empty, offsetof(vmem_magazine_t, mag_node));

	for (int c = 0; c < vmem_max_cpus; c++) {
		vmem_cpu_t *cpu = &vm->vm_cpu[c];
		(void) pthread_mutex_init(&cpu->cpu_lock, NULL);
	}

	vm->vm_mag_disabled = 0;

	return (0);
}

static void
vmem_magazine_fini(vmem_t *vm)
{
	vmem_magazine_purge(vm);

	list_fini(&vm->vm_mag_full);
	list_fini(&vm->vm_mag_empty);

	for (int c = 0; c < vmem_max_cpus; c++) {
		vmem_cpu_t *cpu = &vm->vm_cpu[c];
		(void) pthread_mutex_destroy(&cpu->cpu_lock);
	}

	vmem_destroy(vm->vm_mag_arena);
	vm->vm_mag_arena = NULL;
}

const vmem_ops_t vmem_magazine_ops = {
	.vop_xalloc = vmem_magazine_xalloc,
	.vop_free = vmem_magazine_free,
	.vop_debug = NULL,
	.vop_add = vmem_magazine_add,
	.vop_remove = vmem_magazine_remove,
	.vop_walk = vmem_magazine_walk,
	.vop_vacate = vmem_magazine_vacate,
	.vop_init = vmem_magazine_init,
	.vop_fini = vmem_magazine_fini,
	.vop_name = "magazine",
	.vop_attr = VMEM_OP_FILTER
};
