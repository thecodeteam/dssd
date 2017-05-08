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

#ifndef	_UT_PCB_H
#define	_UT_PCB_H

#include <stdint.h>
#include <stdio.h>
#include <vmem.h>
#include <tree.h>

#ifdef	__cplusplus
extern "C" {
#endif

typedef struct ut_var {
	const char *var_name;
	uint8_t var_code;
	uint16_t var_type;
	void (*var_cook)(struct ut_pcb *, struct ut_node *);
} ut_var_t;

typedef struct ut_str {
	tree_node_t str_node;
	const ut_var_t *str_vref;
	char *str_data;
	size_t str_size;
} ut_str_t;

typedef struct ut_pcb {
	struct utrace_handle *pcb_hdl;
	tree_t pcb_strings;
	vmem_t *pcb_nodes;
	ut_node_t *pcb_root;
	int pcb_depth;
	FILE *pcb_stdin;
	int pcb_cstate;
	int pcb_braces;
	int pcb_bracks;
	int pcb_parens;
	int pcb_errs;
	int pcb_warns;
} ut_pcb_t;

extern const ut_str_t *utrace_pcb_string(ut_pcb_t *, const char *);
extern void utrace_pcb_init(utrace_handle_t *, ut_pcb_t *, FILE *);
extern void utrace_pcb_fini(utrace_handle_t *, ut_pcb_t *);

#ifdef	__cplusplus
}
#endif

#endif	/* _UT_PCB_H */
