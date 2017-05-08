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

#include <sys/types.h>
#include <sys/wait.h>

#include <unistd.h>
#include <strings.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>

#include <utrace_impl.h>

static void
utrace_cg_trace(ut_pcb_t *pcb, ut_file_t *file, ut_node_t *f)
{
	const ut_var_t *v = f->node_value.l_str->str_vref;
	ut_node_t *arg;

	uint8_t ins[8] = { 0 };
	uint8_t i = 0;

	if (f->node_type != UT_TYPE_FUNC) {
		yyuterror(&f->node_loc, pcb, "identifier is not a function: %s",
		    f->node_value.l_str->str_data);
		return;
	}

	ins[i++] = UT_OPC_ENCODE(v->var_code);

	for (arg = f->node_list; arg != NULL &&
	    i < sizeof (ins); arg = arg->node_link) {
		ins[0] = UT_ARG_ENCODE(ins[0], i);
		switch (arg->node_token) {
		case UT_TOK_INT:
			ins[i++] = (uint8_t)arg->node_value.l_int;
			break;
		default:
			ins[i++] = arg->node_value.l_str->str_vref->var_code;
			break;
		}
	}

	if (arg != NULL) {
		yyuterror(&arg->node_loc, pcb, "argument limit exceeded: %s",
		    f->node_value.l_str->str_data);
	}

	utrace_file_write(file, UT_FILE_SECT_CODE, ins, sizeof (ins));
}

static uint32_t
utrace_cg_probe(ut_pcb_t *pcb, ut_file_t *file, ut_node_t *p)
{
	uint32_t n = 0;
	ut_file_probe_t pr;
	ut_node_t *c;

	for (; p != NULL; p = p->node_link, n++) {
		bzero(&pr, sizeof (pr));
		pr.utfp_code = utrace_file_wroff(file, UT_FILE_SECT_CODE);

		for (c = p->node_lhs; c != NULL; c = c->node_link) {
			if (c->node_type != c->node_list->node_type) {
				yyuterror(&c->node_loc, pcb, "probe parameter "
				    "type does not match argument type: %s",
				    c->node_value.l_str->str_data);
				continue;
			}

			switch (c->node_value.l_str->str_vref->var_code) {
			case UT_VAR_EVENT:
				pr.utfp_event = utrace_file_wroff(
				    file, UT_FILE_SECT_STR);
				utrace_file_write(file, UT_FILE_SECT_STR,
				    c->node_list->node_value.l_str->str_data,
				    c->node_list->node_value.l_str->str_size);
				break;

			case UT_VAR_FILE:
				pr.utfp_file = utrace_file_wroff(
				    file, UT_FILE_SECT_STR);
				utrace_file_write(file, UT_FILE_SECT_STR,
				    c->node_list->node_value.l_str->str_data,
				    c->node_list->node_value.l_str->str_size);
				break;

			case UT_VAR_LINE:
				pr.utfp_line = c->node_list->node_value.l_int;
				break;

			default:
				yyuterror(&c->node_loc, pcb,
				    "invalid probe parameter: %s",
				    c->node_value.l_str->str_data);
			}
		}

		for (c = p->node_rhs; c != NULL; c = c->node_link) {
			utrace_cg_trace(pcb, file, c);
			pr.utfp_clen++;
		}

		utrace_file_write(file, UT_FILE_SECT_PROBE, &pr, sizeof (pr));
	}

	return (n);
}

/*
 * Compile the specified input file into an encoded object file.  Our entire
 * scheme is simple enough that all the passes can be done in one function:
 *
 * 1. Set up the pcb for sharing state across ut_lex, ut_grammar, and ut_parser.
 * 2. yyutparse() to lex and parse the input file and construct the parse tree.
 * 3. utrace_node_walk() the parse tree to assign types and resolve identifiers.
 * 4. Run cg on the parse tree with no file allocated to determine sizing.
 * 5. utrace_file_alloc() to allocate the file and relocate the sections.
 * 6. Run on the parse tree again to actually emit the binary object file.
 * 7. Wrap up the result object file buffer in a utrace_request_t and return it.
 */
utrace_request_t *
utrace_fcompile(utrace_handle_t *uhp, FILE *fp)
{
	utrace_request_t *r = NULL;
	ut_pcb_t pcb;

	ut_file_t file;
	ut_file_header_t fhdr;
	uint32_t prc;

	bzero(&file, sizeof (file));
	utrace_pcb_init(uhp, &pcb, fp);

	if (yyutparse(&pcb) != 0)
		goto out;

	if (pcb.pcb_root == NULL) {
		(void) utrace_null(uhp, EINVAL, "empty utrace input file");
		pcb.pcb_errs++;
		goto out;
	}

	if (utrace_node_walk(&pcb, pcb.pcb_root, NULL, NULL) != 0)
		goto out;

	utrace_file_write(&file, UT_FILE_SECT_HDR, &fhdr, sizeof (fhdr));
	prc = utrace_cg_probe(&pcb, &file, pcb.pcb_root);

	if (pcb.pcb_errs != 0)
		goto out;

	utrace_file_alloc(&file);
	bzero(&fhdr, sizeof (fhdr));

	fhdr.utfh_ident[FHDR_IDENT_MAG0] = FHDR_IDMAG_MAG0;
	fhdr.utfh_ident[FHDR_IDENT_MAG1] = FHDR_IDMAG_MAG1;
	fhdr.utfh_ident[FHDR_IDENT_MAG2] = FHDR_IDMAG_MAG2;
	fhdr.utfh_ident[FHDR_IDENT_MAG3] = FHDR_IDMAG_MAG3;

	fhdr.utfh_wsize = __WORDSIZE;
	fhdr.utfh_border = __BYTE_ORDER;
	fhdr.utfh_proff = (uint32_t)sizeof (fhdr);
	fhdr.utfh_prlen = prc;

	utrace_file_write(&file, UT_FILE_SECT_HDR, &fhdr, sizeof (fhdr));
	(void) utrace_cg_probe(&pcb, &file, pcb.pcb_root);
out:
	if (pcb.pcb_errs != 0) {
		vmem_free(vmem_heap, file.utfi_data, file.utfi_size);
	} else {
		r = vmem_alloc(vmem_heap, sizeof (*r), VM_SLEEP);
		r->req_buf = file.utfi_data;
		r->req_len = file.utfi_size;
	}

	utrace_pcb_fini(uhp, &pcb);
	return (r);
}

utrace_request_t *
utrace_compile(utrace_handle_t *uhp, const char *file)
{
	utrace_request_t *rp;
	FILE *fp;

	if ((fp = fopen(file, "r")) == NULL)
		return (utrace_null(uhp, errno, "failed to open %s", file));

	rp = utrace_fcompile(uhp, fp);
	(void) fclose(fp);
	return (rp);
}
