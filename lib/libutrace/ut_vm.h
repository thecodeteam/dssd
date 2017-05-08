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

#ifndef	_UT_VM_H
#define	_UT_VM_H

#include <stdint.h>
#include <stdarg.h>

#ifdef	__cplusplus
extern "C" {
#endif

enum ut_opcode {
	UT_OPC_TRACE,
	UT_OPC_PRINT,
	UT_OPC_ABORT,
	UT_OPC_STOP,
	UT_OPC_PROF_BEGIN,
	UT_OPC_PROF_END,
	UT_OPC_MAX = 32
};

/*
 * Note: some opcodes may interpret the ut_vacode in a context-specific way,
 * e.g. as an integer.
 */
enum ut_vacode {
	UT_VAR_NONE,
	UT_VAR_FUNCTION,
	UT_VAR_FORMAT,
	UT_VAR_ARGS,
	UT_VAR_ERRNO,
	UT_VAR_STACK,
	UT_VAR_CALLER,
	UT_VAR_FRAME,
	UT_VAR_CYCLES,
	UT_VAR_HRTIME,
	UT_VAR_CPUID,
	UT_VAR_TID,
	UT_VAR_PRID,
	UT_VAR_EVENT,
	UT_VAR_EVENTID,
	UT_VAR_FILE,
	UT_VAR_LINE,
	UT_VAR_MAX = 64
};

struct ut_obj;
struct ut_ecb;

#define	UT_VMS_FRAMES	18
#define	UT_VMS_FSKIP	2

typedef struct utrace_vms {
	uint32_t utvm_size[UT_VAR_MAX];
	struct ut_obj *utvm_object;
	const char *utvm_function;
	const char *utvm_format;
	va_list utvm_args;
	int utvm_errno;
	int utvm_depth;
	uintptr_t utvm_stack[UT_VMS_FRAMES - UT_VMS_FSKIP];
	const void *utvm_caller;
	const void *utvm_frame;
	uint64_t utvm_cycles;
	uint64_t utvm_hrtime;
	int utvm_cpuid;
	pthread_t utvm_tid;
	int utvm_prid;
	const char *utvm_event;
	int utvm_eventid;
	const char *utvm_file;
	uint32_t utvm_line;
} utrace_vms_t;

/*
 * Simple instruction encoding for our microscopic virtual machine: we use
 * a 64-bit integer to encode an opcode, argument count, and up to 7 arguments.
 * The encoding is depicted in bytes and bits as follows:
 *
 * 7..B7..0 7..B6..0 7..B5..0 7..B4..0 7..B3..0 7..B2..0 7..B1..0 7..B0..0
 * RRVVVVVV RRVVVVVV RRVVVVVV RRVVVVVV RRVVVVVV RRVVVVVV RRVVVVVV OOOOOCCC
 *
 *     RR - 00    - reserved for future use
 * VVVVVV - 0..63 - ut_vacode variable id
 *  OOOOO - 0..31 - ut_opcode operand id
 *    CCC - 0..7  - number of variables
 *
 * The fixed encoding makes it simpler for us to precalculate all of the data
 * and sizes referenced by an enabling without having to decode the operand.
 */

#define	UT_OPC_ENCODE(opc)	((opc) << 3)
#define	UT_ARG_ENCODE(opc, len)	(((opc) & ~7) | ((len) & 7))

#define	UT_INS_OPCODE(ins)	(((uint8_t)ins) >> 3)
#define	UT_INS_ARGLEN(ins)	(((uint8_t)ins) & 7)
#define	UT_INS_ARGVAR(ins, arg)	((uint8_t)((ins) >> (((arg) + 1) * 8)))

extern void utrace_vm_load(utrace_probe_t *, utrace_vms_t *,
    const char *, enum utrace_event, const char *, va_list, enum ut_vacode);

extern void utrace_vm_exec(utrace_probe_t *, utrace_vms_t *, struct ut_ecb *);

#ifdef	__cplusplus
}
#endif

#endif	/* _UT_VM_H */
