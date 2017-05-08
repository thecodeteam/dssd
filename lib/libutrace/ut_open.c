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

#include <utrace_impl.h>

__thread uint8_t UT_depth;
__thread ut_buf_t *UT_self;
utrace_handle_t UT_ctor;
ut_obj_t UT_exec;

void *
utrace_thread_init(size_t size)
{
	if (UT_self == NULL || UT_self->utbuf_size != size) {
		utrace_buf_destroy(UT_self);
		UT_self = utrace_buf_create(size);
	}
	return (UT_self);
}

void
utrace_thread_fini(void)
{
	utrace_buf_destroy(UT_self);
	UT_self = NULL;
}

static void
__attribute__((constructor))
utrace_init(void)
{
	utrace_handle_t *uhp = &UT_ctor;

	UT_printf = vfprintf;
	UT_tracef = vsnprintf;
	UT_stdout = stdout;

	uhp->uth_dbg = getenv("UTRACE_DEBUG") != NULL;
	uhp->uth_obj = &UT_exec;

	utrace_obj_init(uhp->uth_obj);
	utrace_obj_load(uhp, uhp->uth_obj, "/proc/self/exe");
	utrace_obj_hold(uhp->uth_obj);

	if (getenv("UTRACE_PROBES") != NULL) {
		utrace_walk(uhp, utrace_list, stdout);
		exit(0);
	}

	utrace_thread_init(sysconf(_SC_PAGESIZE));
	utrace_profile(NULL);
}

static void
__attribute__((destructor))
utrace_fini(void)
{
	(void) yyutlex_destroy();
	utrace_thread_fini();
	utrace_obj_rele(UT_ctor.uth_obj);
}

utrace_handle_t *
utrace_open_self(void)
{
	utrace_handle_t *uhp = vmem_zalloc(vmem_heap, sizeof (*uhp), VM_SLEEP);

	uhp->uth_dbg = getenv("UTRACE_DEBUG") != NULL;
	uhp->uth_obj = &UT_exec;

	utrace_obj_hold(uhp->uth_obj);
	return (uhp);
}

void
utrace_close(utrace_handle_t *uhp)
{
	if (uhp == NULL)
		return; /* simplify caller code */

	utrace_disable(uhp);
	utrace_obj_rele(uhp->uth_obj);
	vmem_free(vmem_heap, uhp, sizeof (*uhp));
}
