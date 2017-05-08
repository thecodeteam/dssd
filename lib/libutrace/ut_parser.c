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

void
utrace_func_empty(ut_pcb_t *pcb, ut_node_t *f)
{
	if (f->node_list != NULL) {
		yyuterror(&f->node_loc, pcb, "unexpected arguments "
		    "for function: %s", f->node_value.l_str->str_data);
	}
}

void
utrace_func_nonempty(ut_pcb_t *pcb, ut_node_t *f)
{
	if (f->node_list == NULL) {
		yyuterror(&f->node_loc, pcb, "expected one or more arguments "
		    "for function: %s", f->node_value.l_str->str_data);
	}
}

void
utrace_func_prof(ut_pcb_t *pcb, ut_node_t *f)
{
	if (f->node_list == NULL || f->node_list->node_token != UT_TOK_INT ||
	    f->node_list->node_link != NULL) {
		yyuterror(&f->node_loc, pcb, "expected one int argument "
		    "for function: %s", f->node_value.l_str->str_data);
	}
}

static ut_node_t *
utrace_node_alloc(const YYLTYPE *lp, ut_pcb_t *pcb)
{
	ut_node_t *n = vmem_alloc(pcb->pcb_nodes, sizeof (*n), VM_SLEEP);

	n->node_token = UT_TOK_EOF;
	n->node_type = UT_TYPE_VOID;
	n->node_loc = *lp;
	n->node_lhs = NULL;
	n->node_rhs = NULL;
	n->node_list = NULL;
	n->node_link = NULL;

	return (n);
}

ut_node_t *
utrace_node_link(ut_node_t *l, ut_node_t *r)
{
	ut_node_t *n;

	if (l == NULL)
		return (r);

	if (r == NULL)
		return (l);

	for (n = l; n->node_link != NULL; n = n->node_link)
		continue;

	n->node_link = r;
	return (l);
}

ut_node_t *
utrace_node_ident(const YYLTYPE *lp, ut_pcb_t *pcb, const ut_str_t *name)
{
	ut_node_t *n = utrace_node_alloc(lp, pcb);

	n->node_token = UT_TOK_IDENT;
	n->node_value.l_str = name;

	return (n);
}

ut_node_t *
utrace_node_int(const YYLTYPE *lp, ut_pcb_t *pcb, unsigned long long val)
{
	ut_node_t *n = utrace_node_alloc(lp, pcb);

	n->node_token = UT_TOK_INT;
	n->node_value.l_int = val;

	return (n);
}

ut_node_t *
utrace_node_float(const YYLTYPE *lp, ut_pcb_t *pcb, long double val)
{
	ut_node_t *n = utrace_node_alloc(lp, pcb);

	n->node_token = UT_TOK_FLOAT;
	n->node_value.l_float = val;

	return (n);
}

ut_node_t *
utrace_node_string(const YYLTYPE *lp, ut_pcb_t *pcb, const ut_str_t *name)
{
	ut_node_t *n = utrace_node_alloc(lp, pcb);

	n->node_token = UT_TOK_STRING;
	n->node_value.l_str = name;

	return (n);
}

ut_node_t *
utrace_node_params(const YYLTYPE *lp, ut_pcb_t *pcb,
    const ut_str_t *name, ut_node_t *args)
{
	ut_node_t *n = utrace_node_alloc(lp, pcb);

	n->node_token = UT_TOK_IDENT;
	n->node_value.l_str = name;
	n->node_list = args;

	return (n);
}

ut_node_t *
utrace_node_op2(const YYLTYPE *lp, ut_pcb_t *pcb,
    enum yytokentype token, ut_node_t *lhs, ut_node_t *rhs)
{
	ut_node_t *n = utrace_node_alloc(lp, pcb);

	n->node_token = token;
	n->node_lhs = lhs;
	n->node_rhs = rhs;

	return (n);
}

static void
utrace_node_rwalk(ut_pcb_t *pcb, ut_node_t *rp,
    ut_node_f *func, void *arg, int depth)
{
	const ut_var_t *vp = NULL;
	ut_node_t *cp;

	switch (rp->node_token) {
	case UT_KEY_ON:
		utrace_dprintf("%*sON\n", depth * 2, "");
		break;

	case UT_TOK_IDENT:
		utrace_dprintf("%*s%s\n", depth * 2, "",
		    rp->node_value.l_str->str_data);

		if ((vp = rp->node_value.l_str->str_vref) == NULL) {
			yyuterror(&rp->node_loc, pcb,
			    "undefined identifier: %s",
			    rp->node_value.l_str->str_data);
			rp->node_type = UT_TYPE_VOID;
		} else {
			if (vp->var_cook != NULL)
				vp->var_cook(pcb, rp);
			rp->node_type = vp->var_type;
		}
		break;

	case UT_TOK_INT:
		utrace_dprintf("%*s%llu\n",
		    depth * 2, "", rp->node_value.l_int);
		rp->node_type = UT_TYPE_INT;
		break;

	case UT_TOK_FLOAT:
		utrace_dprintf("%*s%Lg\n",
		    depth * 2, "", rp->node_value.l_float);
		rp->node_type = UT_TYPE_FLOAT;
		break;

	case UT_TOK_STRING:
		utrace_dprintf("%*s\"%s\"\n",
		    depth * 2, "", rp->node_value.l_str->str_data);
		rp->node_type = UT_TYPE_STRING;
		break;
	}

	for (cp = rp->node_lhs; cp != NULL; cp = cp->node_link)
		utrace_node_rwalk(pcb, cp, func, arg, depth + 1);

	for (cp = rp->node_rhs; cp != NULL; cp = cp->node_link)
		utrace_node_rwalk(pcb, cp, func, arg, depth + 1);

	for (cp = rp->node_list; cp != NULL; cp = cp->node_link)
		utrace_node_rwalk(pcb, cp, func, arg, depth + 1);

	if (func != NULL)
		func(pcb, rp, arg);
}

int
utrace_node_walk(ut_pcb_t *pcb, ut_node_t *rp, ut_node_f *func, void *arg)
{
	for (; rp != NULL; rp = rp->node_link)
		utrace_node_rwalk(pcb, rp, func, arg, 0);

	return (pcb->pcb_errs);
}
