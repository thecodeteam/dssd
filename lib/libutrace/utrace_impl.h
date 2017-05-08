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

#ifndef	_UTRACE_IMPL_H
#define	_UTRACE_IMPL_H

#include <pthread.h>
#include <unistd.h>
#include <strings.h>
#include <string.h>
#include <errno.h>

#include <utrace.h>
#include <vmem.h>
#include <tree.h>
#include <p2.h>
#include <tree.h>
#include <vmem.h>
#include <utrace.h>

#ifdef	__cplusplus
extern "C" {
#endif

#ifndef	YYSTYPE
#include <ut_grammar.h>
#define	YYSTYPE	YYSTYPE
#endif

#include <ut_parser.h>
#include <ut_subr.h>
#include <ut_file.h>
#include <ut_obj.h>
#include <ut_pcb.h>
#include <ut_buf.h>
#include <ut_vm.h>

typedef struct ut_ecb {
	struct ut_ecb *utecb_prev;
	struct ut_ecb *utecb_next;
	uint64_t utecb_vars;
	uint64_t *utecb_code;
	uint32_t utecb_clen;
	uint16_t utecb_errors;
	uint16_t utecb_drops;
} ut_ecb_t;

struct utrace_request {
	void *req_buf;
	size_t req_len;
};

struct utrace_handle {
	int uth_dbg;
	ut_obj_t *uth_obj;
	utrace_request_t *uth_req;
};

enum utrace_event {
	EVENT_UNKNOWN = -1
};

extern void utrace_func_empty(ut_pcb_t *, ut_node_t *);
extern void utrace_func_nonempty(ut_pcb_t *, ut_node_t *);
extern void utrace_func_prof(ut_pcb_t *, ut_node_t *);

extern utrace_print_f *UT_printf __attribute__((format(printf, 2, 0)));
extern utrace_trace_f *UT_tracef __attribute__((format(printf, 3, 0)));

extern FILE *UT_stdout;
extern __thread uint8_t UT_depth;
extern __thread ut_buf_t *UT_self;
extern utrace_handle_t UT_ctor;
extern ut_obj_t UT_exec;
extern utrace_prof_ops_t UT_prof;

#ifdef	__cplusplus
}
#endif

#endif	/* _UTRACE_IMPL_H */
