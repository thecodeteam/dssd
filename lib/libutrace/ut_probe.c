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

/*
 * UTrace: Sub-Microsecond Microscopic Dynamic Tracing
 *
 * UTrace is essentially a portable, userland-only, miniature DTrace based on
 * my experience designing, implementing, and using DTrace on Solaris.  It does
 * not provide the vast swath of DTrace functionality (not surprising since
 * this was written in nine days, not two years), but does maintain several
 * of the key features and several improvements specifically for userland i/o.
 *
 * The basic idea is that every utrace() "call" in the target program is in
 * fact a no-op that we can discover on-the-fly, and go hot-patch with a branch
 * to a dead piece of setup code that will call into _utrace_probe() and run
 * our miniature virtual machine to execute an instrumentation request.
 *
 * For more details on DTrace and dynamic tracing principles, refer to the
 * paper "Dynamic Instrumentation of Production Systems", in ATEC '04
 * Proceedings of the 2004 USENIX Annual Technical Conference.
 *
 * UTrace Design Principles, leveraged from DTrace:
 *
 * - zero probe-effect when tracing is not enabled
 * - minimal probe-effect that scales with the query when tracing is enabled
 * - probes and actions can be defined programmatically by the user
 * - safety mechanisms to ensure that queries cannot crash the target program
 *
 * UTrace Improvements for High-Performance Userland I/O Instrumentation:
 *
 * - Sub-microsecond probe overhead.  Since we're actually running *in* the
 *   target process and not trapping into the kernel for an enabled probe, we
 *   trade universal tracing (DTrace) for lower enabled probe effect (UTrace).
 *   It is possible to enable a dynamic probe on every I/O in our data path,
 *   yet see less than a microsecond of enabled probe effect as I/O's execute.
 *
 * - Probe argument assembly that is out of the I-cache hot path when disabled.
 *   Using the GCC Kung Fu (tm) in <utrace.h>, we end up with even less code
 *   impact than that used by DTrace PID/USDT on Solaris: in our method the
 *   probe argument assembly is not part of the function's I-cache footprint.
 *
 * - Source code awareness.  By designing for instrumenting C using GCC, we're
 *   enable to incorporate source-code information into the probe calls,
 *   including user-defined event class, source file name and line number,
 *   and user-defined argument formatting including any printf extensions.
 *
 * UTrace Not Yet Implemented, but easily achievable based on current design:
 *
 * - utrace command-line utility to read ring buffers from proc or core
 * - utrace command-line utility to enable tracing on a running process
 * - utrace probes in shared libraries in addition to a.out
 * - tunable per-thread buffering policy: ring/fill/switch
 * - aggregations in some limited form using libustat histograms
 *
 * UTrace Not Implemented because this is more like a full DTrace port, and
 * would be better solved by a full port or just running DTrace on Solaris:
 *
 * - multiple providers including profile timers and in-kernel probes
 * - complete type declaration and expression compiler for probes
 * - complete aggregation support for arbitrary expression tuples
 * - stability, translators, versioning, and other syntactic sugar
 */

#include <sys/types.h>
#include <sys/mman.h>

#include <strings.h>
#include <unistd.h>
#include <fnmatch.h>

#include <utrace_impl.h>

void
utrace_walk(utrace_handle_t *uhp, utrace_probe_f *func, void *arg)
{
	utrace_probe_t *p = uhp->uth_obj->utob_probev;
	utrace_probe_t *q = p + uhp->uth_obj->utob_probec;

	for (; p < q; p++)
		func(uhp, p, arg);
}

void
utrace_list(utrace_handle_t *uhp, utrace_probe_t *p, void *fp)
{
	(void) fprintf(fp, "%4u %-24s line %-4d %s\n",
	    p->prb_prid, p->prb_file, p->prb_line, p->prb_event);
}

#if defined(__i386__) || defined(__x86_64__)

/*
 * For now we only support instrumenting the executable's object file, so we
 * just look up our global UT_exec handle and use that to find the probe data.
 * The probe 'p' given here is the unrelocated offset in the .utrace
 * ELF section, so relocate it based on our in-memory utob_probev.
 *
 * Once we have a probe and its ECB chain, we take the logical OR of the
 * variables referenced by those ECBs, and then load the virtual machine with
 * only those variables we need.  The virtual machine loading occurs once
 * before any ECB executes to ensure everyone sees the same state (e.g. it
 * would be odd if every call to trace(hrtime) or trace(cpuid) during a
 * single probe firing resulted in tracing different values).
 */
inline void
__attribute__((always_inline))
_utrace_vprobe(utrace_probe_t *p, const char *func,
    utrace_event_t event, const char *format, va_list ap)
{
	ut_obj_t *obj = &UT_exec;
	uint64_t vars = 0;
	utrace_vms_t vms;

	if (UT_depth != 0)
		return; /* drop any attempt at recursive probe entry */

	UT_depth++;

	vms.utvm_object = obj;
	p = obj->utob_probev + (ptrdiff_t)p / sizeof (utrace_probe_t);

	for (ut_ecb_t *ecb = p->prb_head; ecb != NULL; ecb = ecb->utecb_next)
		vars |= ecb->utecb_vars;

	for (enum ut_vacode v = 0; v < UT_VAR_MAX; v++) {
		if (vars & (1ULL << v))
			utrace_vm_load(p, &vms, func, event, format, ap, v);
	}

	for (ut_ecb_t *ecb = p->prb_head; ecb != NULL; ecb = ecb->utecb_next)
		utrace_vm_exec(p, &vms, ecb);

	UT_depth--;
}

void
_utrace_probe(utrace_probe_t *p, const char *func,
    utrace_event_t event, const char *format, ...)
{
	va_list ap;

	va_start(ap, format);
	_utrace_vprobe(p, func, event, format, ap);
	va_end(ap);
}

static int
utrace_patch(utrace_handle_t *uhp,
    uint8_t *dst, const uint8_t *src, size_t src_len)
{
	const size_t pgsize = sysconf(_SC_PAGESIZE);
	uint8_t *p, *q;

	p = (uint8_t *)P2ALIGN((uintptr_t)dst, pgsize);
	q = (uint8_t *)P2ROUNDUP((uintptr_t)dst + src_len, pgsize);

	if (mprotect(p, q - p, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
		return (utrace_error(uhp, errno, "failed to set r/w/x on "
		    "[%p, +%zx) for patch", (void *)p, (size_t)(q - p)));
	}

	bcopy(src, dst, src_len);
	__builtin___clear_cache(dst, dst + src_len);

	if (mprotect(p, q - p, PROT_READ | PROT_EXEC) != 0) {
		return (utrace_error(uhp, errno, "failed to set r/x on "
		    "[%p, +%zx) for patch", (void *)p, (size_t)(q - p)));
	}

	return (0);
}

static void
utrace_probe_attach(utrace_probe_t *p,
    const utrace_request_t *r, const ut_file_probe_t *fp)
{
	ut_ecb_t *ecb = vmem_zalloc(vmem_heap, sizeof (*ecb), VM_SLEEP);

	ut_ecb_t *h = p->prb_head;
	ut_ecb_t *t = p->prb_tail;

	ecb->utecb_code = (uint64_t *)(r->req_buf + fp->utfp_code);
	ecb->utecb_clen = fp->utfp_clen;

	/*
	 * Precalculate the mask of referenced variables for this ECB, such
	 * that _utrace_vprobe() can immediately load only the needed state.
	 */
	for (const uint64_t *cip = ecb->utecb_code;
	    cip < ecb->utecb_code + ecb->utecb_clen; cip++) {
		for (uint8_t arg = 0; arg < UT_INS_ARGLEN(*cip); arg++)
			ecb->utecb_vars |= 1 << UT_INS_ARGVAR(*cip, arg);
	}

	if (h == NULL)
		p->prb_head = ecb;

	if (t != NULL)
		t->utecb_next = ecb;

	p->prb_tail = ecb;
}

static void
utrace_probe_detach(utrace_probe_t *p, ut_ecb_t *ecb)
{
	ut_ecb_t *ep, **epp;

	for (epp = (ut_ecb_t **)&p->prb_head;
	    (ep = *epp) != NULL; epp = &ep->utecb_next) {
		if (ep == ecb)
			break;
	}

	if (ep == ecb)
		*epp = ecb->utecb_next;

	if (p->prb_tail == ecb)
		p->prb_tail = ecb->utecb_next;

	vmem_free(vmem_heap, ecb, sizeof (*ecb));
}

static int
utrace_match(utrace_probe_t *p, const utrace_request_t *r)
{
	const ut_file_header_t *hp = (ut_file_header_t *)r->req_buf;
	const ut_file_probe_t *fp = r->req_buf + hp->utfh_proff;
	const ut_file_probe_t *ep = fp + hp->utfh_prlen;

	const char *f1, *f2;
	int m = 0;

	for (; fp < ep; fp++) {
		if (fp->utfp_line != 0 && fp->utfp_line != p->prb_line)
			continue;

		if (fp->utfp_event != 0 && fnmatch(
		    r->req_buf + fp->utfp_event, p->prb_event, 0) != 0)
			continue;

		if ((f1 = strrchr(p->prb_file, '/')) != NULL)
			f1++;
		else
			f1 = p->prb_file;

		if (strchr(r->req_buf + fp->utfp_file, '/') != NULL)
			f2 = p->prb_file;
		else
			f2 = f1;

		if (fp->utfp_file != 0 && fnmatch(
		    r->req_buf + fp->utfp_file, f2, 0) != 0)
			continue;

		utrace_probe_attach(p, r, fp);
		m++;
	}

	return (m);
}

static void
utrace_enable_one(utrace_handle_t *uhp, utrace_probe_t *p, void *arg)
{
	uint8_t buf[5];
	int32_t r32;

	if (utrace_match(p, arg) == 0)
		return; /* no ecb's attached, do not enable */

	/*
	 * The calculation for the jump target displacement is always
	 * destination - (source + 5).  5 is the size of the JMP rel32
	 * instruction being inserted.  The source is the address of the
	 * jump instruction; the destination is the address to which to
	 * jump.  The size of the jump instruction is added to the source
	 * when calculating the relative displacement because the instruction
	 * pointer used at run time will have been advanced to the next
	 * instruction following the jump when determining the destination
	 * address from RIP + displacement.
	 */
	r32 = (int32_t)(p->prb_dst - p->prb_src) - sizeof (buf);

	buf[0] = 0xe9; /* JMP rel32 */
	bcopy(&r32, &buf[1], sizeof (r32));
	utrace_patch(uhp, p->prb_src, buf, sizeof (buf));
}

void
utrace_enable(utrace_handle_t *uhp, utrace_request_t *r)
{
	if (uhp->uth_req != NULL)
		utrace_disable(uhp);

	(void) pthread_mutex_lock(&uhp->uth_obj->utob_prlock);
	utrace_walk(uhp, utrace_enable_one, r);
	(void) pthread_mutex_unlock(&uhp->uth_obj->utob_prlock);

	uhp->uth_req = r;
}

static void
utrace_disable_one(utrace_handle_t *uhp, utrace_probe_t *p, void *arg)
{
	uint8_t nop[5] = { utrace_probe_nopb };

	if (p->prb_head != NULL)
		utrace_patch(uhp, p->prb_src, nop, sizeof (nop));

	while (p->prb_head != NULL)
		utrace_probe_detach(p, p->prb_head);
}

void
utrace_disable(utrace_handle_t *uhp)
{
	utrace_request_t *r;

	if ((r = uhp->uth_req) == NULL)
		return; /* nothing enabled */

	(void) pthread_mutex_lock(&uhp->uth_obj->utob_prlock);
	utrace_walk(uhp, utrace_disable_one, NULL);
	(void) pthread_mutex_unlock(&uhp->uth_obj->utob_prlock);

	vmem_free(vmem_heap, r->req_buf, r->req_len);
	vmem_free(vmem_heap, r, sizeof (*r));
	uhp->uth_req = NULL;
}
#else

/* utrace probes are not supported for this port: provide stubs */

void
utrace_enable(utrace_handle_t *uhp, utrace_request_t *r)
{
}

void
utrace_disable(utrace_handle_t *uhp)
{
}

#endif  /* defined(__i386__) || defined(__x86_64__) */
