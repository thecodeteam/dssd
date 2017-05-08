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

#include <dlfcn.h>
#include <fnmatch.h>
#include <getpcstack.h>
#include <vmem_impl.h>

/*
 * ============================================================================
 * Debug operations
 * ============================================================================
 */
typedef struct vmem_kv {
	const char *kv_key;	/* key name */
	size_t *kv_valp;	/* pointer to value */
	size_t kv_value;	/* default value */
	int kv_alias;		/* key is shorthand for *valp = value */
	int kv_default;		/* kv_value is default value */
} vmem_kv_t;

static void
vmem_debug_symbol(void *addr, Dl_info *dli)
{
	const char *slash;

	if (dladdr(addr, dli) == 0) {
		dli->dli_fname = "";
		dli->dli_sname = "";
		dli->dli_saddr = NULL;
	}

	if ((slash = strrchr(dli->dli_fname, '/')) != NULL) {
		dli->dli_fname = slash + 1;
	}
}

static void
__attribute__((noreturn))
vmem_debug_usage(vmem_kv_t *kv_map, vmem_kv_t *kv_end)
{
	vmem_kv_t *kv;

	vmem_printf("\nUsage: VMEM_DEBUG=name[:option[=value]...],...\n\n");
	vmem_printf("  name: arena name, fnmatch(3) pattern, or 'all'\n");

	vmem_printf("  options: ");

	for (kv = kv_map; kv < kv_end; kv++) {
		if (kv->kv_alias)
			vmem_printf("%s", kv->kv_key);
		else
			vmem_printf("%s[=%zu]", kv->kv_key, kv->kv_value);
		vmem_printf("%c", kv + 1 == kv_end ? '\n' : ',');
	}

	vmem_printf("\n"
	    "By default, debugging is off for all arenas.\n"
	    "Specifying 'name' enables debugging for that arena.\n"
	    "Options are cumulative; when in conflict, the last setting wins.\n"
	    "\nExamples:\n"
	    "  all            (debug 'on' for all arenas with default values)\n"
	    "  all,foo:off    (debug all arenas except foo)\n"
	    "  vmem_heap_*    (debug the vmem_heap_* arenas)\n"
	    "  foo:tx=4       (debug foo, keeping 4 prior transactions)\n"
	    "  foo:verify=400 (debug foo, verify up to 400 bytes)\n"
	    "  foo:content=80 (debug foo, save 80 bytes of content upon free)\n"
	    "  foo:tx=4:verify=400:content=80 (previous three combined)\n"
	    "  foo:zmo        (debug foo, using zero memory overhead mode)\n"
	    "  foo:tx=4,bar   (debug foo with 4 tx, bar with default)\n"
	    "  usage          (this message)\n");

	exit(1);
}

/*
 * Set vm's debug settings based on the VMEM_DEBUG environment variable,
 * modified by vm->vm_flag's VM_DEBUG, VM_NODEBUG, or VM_MINDEBUG settings.
 */
void
vmem_debug_parse(vmem_t *vm)
{
	const char *envstr = getenv("VMEM_DEBUG");
	char empty[1] = "";
	char *str = envstr ? alloca(strlen(envstr) + 1) : empty;
	char *options, *pattern, *kvstr, *key, *value;
	size_t debug, tx, dbsize, verify, content;

	vmem_kv_t kv_map[] = {
		/* name		variable	value	alias	default? */
		{ "off",	&debug,		0,	1,	1	},
		{ "on",		&debug,		1,	1,	0	},
		{ "zmo",	&debug,		2,	1,	0	},
		{ "tx",		&tx,		2,	0,	1	},
		{ "verify",	&verify,	256,	0,	1	},
		{ "content",	&content,	256,	0,	1	},
	};
	vmem_kv_t *kv;
	vmem_kv_t *kv_end = (void *)kv_map + sizeof (kv_map);

	for (kv = kv_map; kv < kv_end; kv++) {
		if (strcmp(kv->kv_key, vm->vm_name) == 0)
			vmem_panic("vmem_create(): reserved name '%s'",
			    vm->vm_name);
		if (kv->kv_default)
			*kv->kv_valp = kv->kv_value;
	}

	if (envstr != NULL)
		(void) strcpy(str, envstr);

	while ((options = strsep(&str, ",")) != NULL) {
		pattern = strsep(&options, ":");
		if (pattern == NULL)
			continue;
		if (strcmp(pattern, "usage") == 0)
			vmem_debug_usage(kv_map, kv_end);
		if (fnmatch(pattern, vm->vm_name, 0) != 0 &&
		    strcmp(pattern, "all") != 0)
			continue;
		debug = 1;
		while ((kvstr = strsep(&options, ":")) != NULL) {
			key = strsep(&kvstr, "=");
			if (key == NULL || key[0] == '\0')
				continue;
			value = strsep(&kvstr, "=");
			for (kv = kv_map; kv < kv_end; kv++) {
				if (strcmp(kv->kv_key, key) == 0)
					break;
			}
			if (kv == kv_end) {
				vmem_printf("bad option '%s'\n", key);
				vmem_debug_usage(kv_map, kv_end);
			}
			if (kv->kv_alias || value == NULL || value[0] == '\0') {
				*kv->kv_valp = kv->kv_value;
			} else {
				*kv->kv_valp = strtoul(value, NULL, 0);
			}
		}
	}

	while (!IS_P2(tx))
		tx = P2CLEARLOWBIT(tx);

	dbsize = offsetof(vmem_debug_t, db_tx[tx]);

	if ((vm->vm_flag & VM_VIRTUAL) || vm->vm_q < sizeof (uint64_t)) {
		verify = 0;
		content = 0;
	}

	/*
	 * If the arena should always have debug enabled, then enable it,
	 * but retain specific settings like "tx=4" from the environment.
	 *
	 * If only minimal debugging overhead is tolerable, use ZMO.
	 *
	 * If the arena should never have debugging enabled, disable it.
	 */
	if (vm->vm_flag & VM_DEBUG)
		debug = 1;

	if ((vm->vm_flag & VM_MINDEBUG) && debug == 1)
		debug = 2;

	if (vm->vm_flag & VM_NODEBUG)
		debug = 0;

	if (debug == 2) {	/* ZMO (zero memory overhead) mode */
		tx = 0;
		dbsize = 0;
		verify = vmem_size_min(verify, vm->vm_object - sizeof (void *));
		content = 0;
		if (verify < sizeof (uint64_t))
			debug = 0;
	}

	if (debug == 0)
		return;

	vm->vm_debug = 1;
	vm->vm_tx = tx;
	vm->vm_dbsize = dbsize;
	vm->vm_verify = verify;
	vm->vm_content = content;
}

static inline void
vmem_debug_verify(vmem_t *vm, void *addr, size_t size, vmem_debug_t *db,
    uint64_t value)
{
	uint64_t delta = 0;
	uint64_t *p = addr;
	size_t count = vmem_size_min(size, vm->vm_verify) >> 3;

	while (count-- != 0)
		delta |= (*p++ - value);

	if (delta != 0)
		vmem_panic_free(vm, addr, size,
		    "modified while free, db %p", db);
}

static inline void
vmem_debug_fill(vmem_t *vm, void *addr, size_t size, uint64_t value)
{
	uint64_t *p = addr;
	size_t count = vmem_size_min(size, vm->vm_verify) >> 3;

	while (count-- != 0)
		*p++ = value;
}

static inline void
vmem_debug_save_content(vmem_t *vm, void *addr, size_t size, vmem_debug_t *db)
{
	uint64_t *src = addr;
	uint64_t *dst = (void *)db + vm->vm_dbsize;
	size_t count = vmem_size_min(size, vm->vm_content) >> 3;

	while (count-- != 0)
		*dst++ = *src++;
}

static inline void
vmem_debug_state_change(vmem_t *vm, void *addr, size_t size, vmem_debug_t *db,
    char old_state, char new_state)
{
	if (db != NULL) {
		if (db->db_redzone != VMEM_DEBUG_REDZONE)
			vmem_panic_free(vm, addr, size,
			    "redzone violation, db %p", db);
		if (db->db_addr != addr)
			vmem_panic_free(vm, addr, size,
			    "wrong address, db %p", db);
		if (db->db_size != size)
			vmem_panic_free(vm, addr, size,
			    "wrong size, db %p", db);
		if (db->db_arena != vm)
			vmem_panic_free(vm, addr, size,
			    "wrong arena, db %p", db);
		if (db->db_state != old_state)
			vmem_panic_free(vm, addr, size,
			    "double %s, db %p",
			    old_state == 'a' ? "free" : "alloc", db);
		db->db_state = new_state;
	}
}

static inline void
vmem_debug_tx(vmem_t *vm, vmem_debug_t *db)
{
	if (vm->vm_tx != 0) {
		vmem_tx_t *tx = &db->db_tx[db->db_txid++ & (vm->vm_tx - 1)];
		tx->tx_timestamp = gethrcycles();
		tx->tx_thread = pthread_self();
		(void) getpcstack(tx->tx_stack, VMEM_TX_STACK, 1);
	}
}

void
vmem_debug_leak_cb(vmem_t *vm, void *addr, size_t size, void *dbarg)
{
	vmem_debug_t *db = vm->vm_dbsize ? dbarg : NULL;

	vmem_printf("%s:  %s=%p  addr=%p  size=%zu  leaked\n",
	    vm->vm_name,
	    db ? "db" : "vm",
	    db ? (void *)db : (void *)vm,
	    addr, size);

	if (db != NULL && vm->vm_tx != 0) {
		int max_tx = db->db_txid - 1;
		int min_tx = max_tx - (int)vm->vm_tx + 1;
		if (min_tx < 0)
			min_tx = 0;
		for (int t = max_tx; t >= min_tx; t--) {
			vmem_tx_t *tx = &db->db_tx[t & (vm->vm_tx - 1)];
			vmem_printf("thread=%p   T+%.09f   txid=%d\n",
			    (void *)tx->tx_thread,
			    hrcyctons(tx->tx_timestamp - vmem_born) / 1.0e9, t);
			for (int d = 0; d < VMEM_TX_STACK; d++) {
				Dl_info dli;
				if (tx->tx_stack[d] == NULL)
					break;
				vmem_debug_symbol(tx->tx_stack[d], &dli);
				vmem_printf("\t%s'%s+%#zx\n",
				    dli.dli_fname, dli.dli_sname,
				    (size_t)(tx->tx_stack[d] - dli.dli_saddr));
			}
		}
	}
}

/*
 * Debug setup.  Sadly, there are two aspects of debugging that can't be
 * layered with complete transparency:
 *
 * 1. The base arena must reserve space for the vmem_debug_t.
 *    This is done by vop_init() when the base arena is created.
 *
 * 2. The debug state must be updated when it changes in the base arena
 *    without going through one of the normal ops, such as when a piece
 *    of vm_slab_partial is first allocated, or when vmem_seg_xalloc()
 *    or vmem_seg_free() split or join segments.  vmem_debug_start()
 *    sets the initial debug state for new memory; vmem_debug_update()
 *    updates db_addr and db_size if they change (e.g. after seg split).
 */
void
vmem_debug_start(vmem_t *vm, void *addr, size_t size, vmem_debug_t *db)
{
	ASSERT(vm == vm->vm_base);

	if (vm->vm_dbsize) {
		db->db_redzone = VMEM_DEBUG_REDZONE;
		db->db_addr = addr;
		db->db_size = size;
		db->db_arena = vm;
		db->db_state = 'f';
		db->db_txid = 0;
	}
	vmem_debug_fill(vm, addr, size, VMEM_DEBUG_FREE);
}

void
vmem_debug_update(vmem_t *vm, void *addr, size_t size, vmem_debug_t *db)
{
	ASSERT(vm == vm->vm_base);

	if (vm->vm_dbsize) {
		db->db_addr = addr;
		db->db_size = size;
	}
	vmem_debug_fill(vm, addr, size, VMEM_DEBUG_FREE);
}

/*
 * ============================================================================
 * Debug ops vector
 * ============================================================================
 */
static void *
vmem_debug_xalloc(vmem_t *vm, size_t size, size_t align, size_t phase, int flag)
{
	void *addr = vmem_xalloc(vm->vm_source, size, align, phase, flag);

	if (addr != NULL) {
		vmem_t *bvm = vm->vm_base;
		vmem_debug_t *db = bvm->vm_ops.vop_debug(bvm, addr, size);
		vmem_debug_state_change(bvm, addr, size, db, 'f', 'a');
		vmem_debug_verify(bvm, addr, size, db, VMEM_DEBUG_FREE);
		vmem_debug_fill(bvm, addr, size, VMEM_DEBUG_ALLOC);
		vmem_debug_tx(bvm, db);
	}

	return (addr);
}

static void
vmem_debug_free(vmem_t *vm, void *addr, size_t size)
{
	if (addr == NULL)
		return;

	/*
	 * In ZMO (zero memory overhead) debugging mode (vm_dbsize == 0),
	 * there is nowhere external to store the allocated/free state.
	 * We therefore check for the 0xdeadbeefdeadbeef pattern in the
	 * first word of the buffer to determine whether it's a double free.
	 * This can in principle lead to false positives, so don't use
	 * ZMO debugging mode if you're freeing buffers that can legitimately
	 * contain 0xdeadbeefdeadbeef in the first word.
	 */
	vmem_t *bvm = vm->vm_base;

	if (bvm->vm_dbsize == 0 && *(uint64_t *)addr == VMEM_DEBUG_FREE)
		vmem_panic_free(vm, addr, size, "apparent double free");

	vmem_debug_t *db = bvm->vm_ops.vop_debug(bvm, addr, size);
	vmem_debug_state_change(bvm, addr, size, db, 'a', 'f');
	vmem_debug_save_content(bvm, addr, size, db);
	vmem_debug_fill(bvm, addr, size, VMEM_DEBUG_FREE);
	vmem_debug_tx(bvm, db);

	vmem_free(vm->vm_source, addr, size);
}

static void
vmem_debug_add(vmem_t *vm, void *addr, size_t size)
{
	vmem_add(vm->vm_source, addr, size);
}

static void
vmem_debug_remove(vmem_t *vm, void *addr, size_t size)
{
	vmem_remove(vm->vm_source, addr, size);
}

static size_t
vmem_debug_walk(vmem_t *vm, vmem_walk_cb *func, void *arg, int w)
{
	return (vmem_walk(vm->vm_source, func, arg, w));
}

static void
vmem_debug_vacate(vmem_t *vm, int v)
{
	if (v & VMEM_VACATE_SELF_ONLY)
		return;

	vmem_vacate(vm->vm_source, v);
}

static int
vmem_debug_init(vmem_t *vm)
{
	return (0);
}

static void
vmem_debug_fini(vmem_t *vm)
{
}

const vmem_ops_t vmem_debug_ops = {
	.vop_xalloc = vmem_debug_xalloc,
	.vop_free = vmem_debug_free,
	.vop_debug = NULL,
	.vop_add = vmem_debug_add,
	.vop_remove = vmem_debug_remove,
	.vop_walk = vmem_debug_walk,
	.vop_vacate = vmem_debug_vacate,
	.vop_init = vmem_debug_init,
	.vop_fini = vmem_debug_fini,
	.vop_name = "debug",
	.vop_attr = VMEM_OP_FILTER
};
