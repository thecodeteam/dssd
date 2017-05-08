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

#include <units.h>
#include <strings.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>

#include <ucore_impl.h>

ssize_t
nt_prstatus_size(NElf_Word type, int fd, off_t off, pid_t tid)
{
	return (ucore_note_size(type, "CORE", sizeof (struct elf_prstatus)));
}

static int
nt_prstatus_sigs(size_t argc, char *argv[], void *data)
{
	struct elf_prstatus *p = data;

	if (argc >= 2 && strcmp(argv[0], "SigPnd:") == 0)
		(void) sscanf(argv[1], "%lx", &p->pr_sigpend);
	else if (argc >= 2 && strcmp(argv[0], "SigBlk:") == 0)
		(void) sscanf(argv[1], "%lx", &p->pr_sighold);

	return (0);
}

static int
nt_prstatus_stat(size_t argc, char *argv[], void *data)
{
	const unsigned long tck_per_s = ucore_clktck;
	const unsigned long us_per_tck = U_MICROSEC / tck_per_s;

	struct elf_prstatus *p = data;
	unsigned long tck;

	(void) sscanf(argv[0], "%d", &p->pr_pid);
	(void) sscanf(argv[3], "%d", &p->pr_ppid);
	(void) sscanf(argv[4], "%d", &p->pr_pgrp);
	(void) sscanf(argv[5], "%d", &p->pr_sid);

	(void) sscanf(argv[13], "%lu", &tck);
	p->pr_utime.tv_sec = tck / tck_per_s;
	p->pr_utime.tv_usec = (tck % tck_per_s) * us_per_tck;

	(void) sscanf(argv[14], "%lu", &tck);
	p->pr_stime.tv_sec = tck / tck_per_s;
	p->pr_stime.tv_usec = (tck % tck_per_s) * us_per_tck;

	(void) sscanf(argv[15], "%lu", &tck);
	p->pr_cutime.tv_sec = tck / tck_per_s;
	p->pr_cutime.tv_usec = (tck % tck_per_s) * us_per_tck;

	(void) sscanf(argv[16], "%lu", &tck);
	p->pr_cstime.tv_sec = tck / tck_per_s;
	p->pr_cstime.tv_usec = (tck % tck_per_s) * us_per_tck;

	p->pr_fpvalid = 1;
	return (0);
}

ssize_t
nt_prstatus_dump(NElf_Word type, int fd, off_t off, pid_t tid)
{
	struct elf_prstatus p;
	siginfo_t sig;

	/*
	 * The current Linux kernel code sets pr_cursig for *every* TID to the
	 * fatal signal, and ignores pr_info.si_code and si_errno entirely.
	 * And of course gdb relies upon this behavior, even though it makes
	 * no sense.  So although what we should be doing here is to call
	 * ptrace(PTRACE_GETSIGINFO) for the non-faulting TIDs, instead we have
	 * to emulate what Linux core files look like even though it's wrong.
	 */
	bzero(&p, sizeof (p));
	ucore_getsig(&sig);

	p.pr_info.si_signo = sig.si_signo;
	p.pr_cursig = sig.si_signo;

	if (tid == ucore_gettid()) {
		p.pr_info.si_code = sig.si_code;
		p.pr_info.si_errno = sig.si_errno;
	}

	(void) ucore_parse(nt_prstatus_sigs, &p,
	    "/proc/%d/task/%d/status", ucore_getpid(), tid);

	(void) ucore_parse(nt_prstatus_stat, &p,
	    "/proc/%d/task/%d/stat", ucore_getpid(), tid);

	if (ptrace(PTRACE_GETREGS, tid, NULL, &p.pr_reg) != 0)
		(void) ucore_error(errno, "failed to get gregs for %d", tid);

	if (tid == ucore_gettid())
		ucore_getreg(&p.pr_reg);

	return (ucore_note_dump(fd, off, type, "CORE", &p, sizeof (p)));
}
