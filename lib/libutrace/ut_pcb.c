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

static const ut_var_t
utrace_pcb_builtin[] = {
	{ "abort", UT_OPC_ABORT, UT_TYPE_FUNC, utrace_func_empty },
	{ "args", UT_VAR_ARGS, UT_TYPE_UINTPTR, NULL },
	{ "caller", UT_VAR_CALLER, UT_TYPE_UINTPTR, NULL },
	{ "cpuid", UT_VAR_CPUID, UT_TYPE_UINT32, NULL },
	{ "cycles", UT_VAR_CYCLES, UT_TYPE_UINT64, NULL },
	{ "errno", UT_VAR_ERRNO, UT_TYPE_INT, NULL },
	{ "event", UT_VAR_EVENT, UT_TYPE_STRING, NULL },
	{ "eventid", UT_VAR_EVENTID, UT_TYPE_INT, NULL },
	{ "file", UT_VAR_FILE, UT_TYPE_STRING, NULL },
	{ "format", UT_VAR_FORMAT, UT_TYPE_STRING, NULL },
	{ "frame", UT_VAR_FRAME, UT_TYPE_UINTPTR, NULL },
	{ "function", UT_VAR_FUNCTION, UT_TYPE_STRING, NULL },
	{ "hrtime", UT_VAR_HRTIME, UT_TYPE_UINT64, NULL },
	{ "line", UT_VAR_LINE, UT_TYPE_INT, NULL },
	{ "prid", UT_VAR_PRID, UT_TYPE_UINT32, NULL },
	{ "print", UT_OPC_PRINT, UT_TYPE_FUNC, utrace_func_nonempty },
	{ "stack", UT_VAR_STACK, UT_TYPE_STRUCT, NULL },
	{ "stop", UT_OPC_STOP, UT_TYPE_FUNC, utrace_func_empty },
	{ "tid", UT_VAR_TID, UT_TYPE_UINTPTR, NULL },
	{ "trace", UT_OPC_TRACE, UT_TYPE_FUNC, utrace_func_nonempty },
	{ "prof_begin", UT_OPC_PROF_BEGIN, UT_TYPE_FUNC, utrace_func_prof },
	{ "prof_end", UT_OPC_PROF_END, UT_TYPE_FUNC, utrace_func_prof },
	{ NULL, 0, 0, NULL }
};

static int
__attribute__((pure))
utrace_pcb_strcmp(const void *lp, const void *rp)
{
	const ut_str_t *s1 = lp;
	const ut_str_t *s2 = rp;

	return (strcmp(s1->str_data, s2->str_data));
}

const ut_str_t *
utrace_pcb_string(ut_pcb_t *pcb, const char *str)
{
	ut_str_t o, *s;

	o.str_size = strlen(str) + 1;
	o.str_data = (char *)str;

	if ((s = tree_lookup(&pcb->pcb_strings, &o)) != NULL)
		return (s);

	s = vmem_alloc(vmem_heap, sizeof (*s), VM_SLEEP);

	s->str_vref = NULL;
	s->str_data = vmem_alloc(vmem_heap, o.str_size, VM_SLEEP);
	s->str_size = o.str_size;

	bcopy(str, s->str_data, s->str_size);
	tree_insert(&pcb->pcb_strings, s);

	return (s);
}

/*
 * Initialize the parser control block (pcb), which includes a tree for unique
 * strings encountered during compilation, and a cache of all parse tree nodes.
 * The pcb is used to share state across ut_lex.l, ut_grammar.y, and ut_parser.c
 */
void
utrace_pcb_init(utrace_handle_t *uhp, ut_pcb_t *pcb, FILE *fp)
{
	const ut_var_t *vp;

	bzero(pcb, sizeof (*pcb));

	tree_init(&pcb->pcb_strings,
	    utrace_pcb_strcmp, offsetof(ut_str_t, str_node));

	pcb->pcb_nodes = vmem_create(&vmem_object_ops,
	    __alignof__(ut_node_t), sizeof (ut_node_t),
	    vmem_page, NULL, NULL, 0, "pcb_%p", pcb);

	for (vp = utrace_pcb_builtin; vp->var_name != NULL; vp++) {
		const ut_str_t *s = utrace_pcb_string(pcb, vp->var_name);
		((ut_str_t *)s)->str_vref = vp;
	}

	pcb->pcb_hdl = uhp;
	pcb->pcb_stdin = fp;
	pcb->pcb_depth = 1;

	yyutinit(pcb);
}

/* ARGSUSED */
static void
ut_str_destroy(void *p, void *arg)
{
	ut_str_t *str = p;
	vmem_free(vmem_heap, str->str_data, str->str_size);
	vmem_free(vmem_heap, str, sizeof (*str));
}

void
utrace_pcb_fini(utrace_handle_t *uhp, ut_pcb_t *pcb)
{
	yyutfini(pcb);
	tree_teardown(&pcb->pcb_strings, ut_str_destroy, NULL);
	tree_fini(&pcb->pcb_strings);
	vmem_vacate(pcb->pcb_nodes, VMEM_VACATE_ALL);
	vmem_destroy(pcb->pcb_nodes);
}
