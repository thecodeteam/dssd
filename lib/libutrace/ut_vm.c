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

#include <sched.h>
#include <signal.h>
#include <alloca.h>

#include <hrtime.h>
#include <getpcstack.h>

#include <utrace_impl.h>

static void
utrace_vm_trace(ut_buf_t *bp, utrace_vms_t *vmp, enum ut_vacode var)
{
	const void *vp = NULL;
	va_list ap;

	switch (var) {
	case UT_VAR_FUNCTION:
		vp = vmp->utvm_function;
		break;
	case UT_VAR_FORMAT:
		vp = vmp->utvm_format;
		break;
	case UT_VAR_ARGS:
		vp = alloca(vmp->utvm_size[var]);
		va_copy(ap, vmp->utvm_args);
		(void) utrace_vtracef((char *)vp, vmp->utvm_size[var],
		    vmp->utvm_format, ap);
		break;
	case UT_VAR_ERRNO:
		vp = &vmp->utvm_errno;
		break;
	case UT_VAR_STACK:
		vp = &vmp->utvm_stack[0];
		break;
	case UT_VAR_CALLER:
		vp = &vmp->utvm_caller;
		break;
	case UT_VAR_FRAME:
		vp = &vmp->utvm_frame;
		break;
	case UT_VAR_CYCLES:
		vp = &vmp->utvm_cycles;
		break;
	case UT_VAR_HRTIME:
		vp = &vmp->utvm_hrtime;
		break;
	case UT_VAR_CPUID:
		vp = &vmp->utvm_cpuid;
		break;
	case UT_VAR_TID:
		vp = &vmp->utvm_tid;
		break;
	case UT_VAR_PRID:
		vp = &vmp->utvm_prid;
		break;
	case UT_VAR_EVENT:
		vp = vmp->utvm_event;
		break;
	case UT_VAR_EVENTID:
		vp = &vmp->utvm_eventid;
		break;
	case UT_VAR_FILE:
		vp = vmp->utvm_file;
		break;
	case UT_VAR_LINE:
		vp = &vmp->utvm_line;
		break;
	}

	if (vp != NULL)
		utrace_buf_write(bp, vp, vmp->utvm_size[var]);
}

static void
utrace_vm_print(FILE *fp, utrace_vms_t *vmp, enum ut_vacode var)
{
	char buf[512];
	va_list ap;

	switch (var) {
	case UT_VAR_FUNCTION:
		utrace_printf(fp, "%s()", vmp->utvm_function);
		break;
	case UT_VAR_FORMAT:
		utrace_printf(fp, "\"%s\"", vmp->utvm_format);
		break;
	case UT_VAR_ARGS:
		va_copy(ap, vmp->utvm_args);
		utrace_vprintf(fp, vmp->utvm_format, ap);
		break;
	case UT_VAR_ERRNO:
		utrace_printf(fp, "errno=%d (%s)",
		    vmp->utvm_errno, strerror(vmp->utvm_errno));
		break;
	case UT_VAR_STACK:
		for (int d = 0; d < vmp->utvm_depth; d++) {
			(void) utrace_obj_name(vmp->utvm_object,
			    vmp->utvm_stack[d], buf, sizeof (buf));
			utrace_printf(fp, "%s()\n", buf);
		}
		break;
	case UT_VAR_CALLER:
		(void) utrace_obj_name(vmp->utvm_object,
		    (uintptr_t)vmp->utvm_caller, buf, sizeof (buf));
		utrace_printf(fp, "caller=%s", buf);
		break;
	case UT_VAR_FRAME:
		utrace_printf(fp, "frame=%p", vmp->utvm_frame);
		break;
	case UT_VAR_CYCLES:
		utrace_printf(fp, "cycles=%jx", vmp->utvm_cycles);
		break;
	case UT_VAR_HRTIME:
		utrace_printf(fp, "hrtime=%jx", vmp->utvm_hrtime);
		break;
	case UT_VAR_CPUID:
		utrace_printf(fp, "cpuid=%d", vmp->utvm_cpuid);
		break;
	case UT_VAR_TID:
		utrace_printf(fp, "tid=%lx", vmp->utvm_tid);
		break;
	case UT_VAR_PRID:
		utrace_printf(fp, "prid=%u", vmp->utvm_prid);
		break;
	case UT_VAR_EVENT:
		utrace_printf(fp, "%s", vmp->utvm_event);
		break;
	case UT_VAR_EVENTID:
		utrace_printf(fp, "eventid=%d", vmp->utvm_eventid);
		break;
	case UT_VAR_FILE:
		utrace_printf(fp, "%s", vmp->utvm_file);
		break;
	case UT_VAR_LINE:
		utrace_printf(fp, "%u", vmp->utvm_line);
		break;
	}
}

static void
utrace_vm_prof_begin(utrace_vms_t *vmp, enum ut_vacode var)
{
	(*UT_prof.utpf_begin)((unsigned)var);
}

static void
utrace_vm_prof_end(utrace_vms_t *vmp, enum ut_vacode var)
{
	(*UT_prof.utpf_end)((unsigned)var);
}

void
__attribute__((format(printf, 5, 0)))
utrace_vm_load(utrace_probe_t *p, utrace_vms_t *vmp,
    const char *func, utrace_event_t event,
    const char *format, va_list ap, enum ut_vacode var)
{
	void *stack[UT_VMS_FRAMES];
	va_list aq;
	int depth;

	switch (var) {
	case UT_VAR_FUNCTION:
		vmp->utvm_size[var] = strlen(func) + 1;
		vmp->utvm_function = func;
		break;
	case UT_VAR_FORMAT:
		vmp->utvm_size[var] = strlen(format) + 1;
		vmp->utvm_format = format;
		break;
	case UT_VAR_ARGS:
		va_copy(vmp->utvm_args, ap);
		va_copy(aq, ap);
		vmp->utvm_size[var] = utrace_vtracef(NULL, 0, format, aq) + 1;
		vmp->utvm_format = format;
		break;
	case UT_VAR_ERRNO:
		vmp->utvm_size[var] = sizeof (vmp->utvm_errno);
		vmp->utvm_errno = errno;
		break;
	case UT_VAR_STACK:
		/* Inlined getpcstack() skips the first frame for us. */
		depth = getpcstack(stack + 1, UT_VMS_FRAMES - 1, 0) + 1;
		for (vmp->utvm_depth = 0; vmp->utvm_depth <
		    depth - UT_VMS_FSKIP; vmp->utvm_depth++)
			vmp->utvm_stack[vmp->utvm_depth] =
			    (uintptr_t)stack[vmp->utvm_depth + UT_VMS_FSKIP];
		vmp->utvm_size[var] = vmp->utvm_depth * sizeof (uintptr_t);
		break;
	case UT_VAR_CALLER:
		vmp->utvm_size[var] = sizeof (vmp->utvm_caller);
		vmp->utvm_caller = __builtin_return_address(UT_VMS_FSKIP);
		break;
	case UT_VAR_FRAME:
		vmp->utvm_size[var] = sizeof (vmp->utvm_frame);
		vmp->utvm_frame = __builtin_frame_address(UT_VMS_FSKIP);
		break;
	case UT_VAR_CYCLES:
		vmp->utvm_size[var] = sizeof (vmp->utvm_cycles);
		vmp->utvm_cycles = gethrcycles();
		break;
	case UT_VAR_HRTIME:
		vmp->utvm_size[var] = sizeof (vmp->utvm_hrtime);
		vmp->utvm_hrtime = gethrtime();
		break;
	case UT_VAR_CPUID:
		vmp->utvm_size[var] = sizeof (vmp->utvm_cpuid);
		vmp->utvm_cpuid = sched_getcpu();
		break;
	case UT_VAR_TID:
		vmp->utvm_size[var] = sizeof (vmp->utvm_tid);
		vmp->utvm_tid = pthread_self();
		break;
	case UT_VAR_PRID:
		vmp->utvm_size[var] = sizeof (vmp->utvm_prid);
		vmp->utvm_prid = p->prb_prid;
		break;
	case UT_VAR_EVENT:
		vmp->utvm_size[var] = strlen(p->prb_event) + 1;
		vmp->utvm_event = p->prb_event;
		break;
	case UT_VAR_EVENTID:
		vmp->utvm_size[var] = sizeof (vmp->utvm_eventid);
		vmp->utvm_eventid = event;
		break;
	case UT_VAR_FILE:
		vmp->utvm_size[var] = strlen(p->prb_file) + 1;
		vmp->utvm_file = p->prb_file;
		break;
	case UT_VAR_LINE:
		vmp->utvm_size[var] = sizeof (vmp->utvm_line);
		vmp->utvm_line = p->prb_line;
		break;
	}
}

void
utrace_vm_exec(utrace_probe_t *p, utrace_vms_t *vmp, ut_ecb_t *ecb)
{
	ut_buf_t *bp = UT_self;
	FILE *fp = UT_stdout;

	const uint64_t *c = ecb->utecb_code;
	const uint64_t *d = c + ecb->utecb_clen;

	for (const uint64_t *cip = c; cip < d; cip++) {
		const uint64_t ins = *cip;
		enum ut_opcode opcode = UT_INS_OPCODE(ins);
		uint8_t opargc = UT_INS_ARGLEN(ins);
		size_t opsize = 0;
		uint32_t ttag[2];

		switch (opcode) {
		case UT_OPC_TRACE:
			if (bp == NULL) {
				ecb->utecb_drops++;
				break;
			}

			for (uint8_t arg = 0; arg < opargc; arg++) {
				opsize += vmp->utvm_size[
				    UT_INS_ARGVAR(ins, arg)];
			}

			/*
			 * Erase entire records until we have enough space for
			 * this new one.  This ensures that utbuf_rptr always
			 * refers to a valid ttag[] with all of its data.
			 */
			while (bp->utbuf_free < sizeof (ttag) + opsize) {
				bcopy(bp->utbuf_rptr, ttag, sizeof (ttag));
				utrace_buf_erase(bp, sizeof (ttag) + ttag[1]);
			}

			ttag[0] = p->prb_prid;
			ttag[1] = opsize;

			utrace_buf_write(bp, ttag, sizeof (ttag));

			for (uint8_t arg = 0; arg < opargc; arg++) {
				utrace_vm_trace(bp, vmp,
				    UT_INS_ARGVAR(ins, arg));
			}
			break;

		case UT_OPC_PRINT:
			if (opargc != 0) {
				utrace_vm_print(fp, vmp,
				    UT_INS_ARGVAR(ins, 0));
			}
			for (uint8_t arg = 1; arg < opargc; arg++) {
				utrace_printf(fp, ", ");
				utrace_vm_print(fp, vmp,
				    UT_INS_ARGVAR(ins, arg));
			}
			utrace_printf(fp, "\n");
			break;

		case UT_OPC_ABORT:
			abort();
			break;

		case UT_OPC_STOP:
			(void) pthread_kill(pthread_self(), SIGSTOP);
			break;

		case UT_OPC_PROF_BEGIN:
			utrace_vm_prof_begin(vmp, UT_INS_ARGVAR(ins, 0));
			break;

		case UT_OPC_PROF_END:
			utrace_vm_prof_end(vmp, UT_INS_ARGVAR(ins, 0));
			break;

		default:
			ecb->utecb_errors++;
		}
	}
}
