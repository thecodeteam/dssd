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

#include <strings.h>
#include <string.h>

#include <ucore_impl.h>

ssize_t
nt_prpsinfo_size(NElf_Word type, int fd, off_t off, pid_t tid)
{
	if (tid != ucore_gettid())
		return (0); /* only for the main thread */

	return (ucore_note_size(type,
	    "CORE", sizeof (struct elf_prpsinfo)));
}

static int
nt_prpsinfo_stat(size_t argc, char *argv[], void *data)
{
	struct elf_prpsinfo *p = data;
	const char states[] = "RSDTZW";

	const char *sp;
	char sname;
	long nicev;

	(void) sscanf(argv[2], "%c", &sname);
	sp = strchr(states, sname);
	(void) sscanf(argv[18], "%ld", &nicev);

	p->pr_state = sp ? (char)(sp - states) : -1;
	p->pr_sname = sname;
	p->pr_zomb = sname == 'Z';
	p->pr_nice = (char)nicev;

	(void) sscanf(argv[8], "%lu", &p->pr_flag);
	(void) sscanf(argv[0], "%d", &p->pr_pid);
	(void) sscanf(argv[3], "%d", &p->pr_ppid);
	(void) sscanf(argv[4], "%d", &p->pr_pgrp);
	(void) sscanf(argv[5], "%d", &p->pr_sid);

	return (0);
}

static int
nt_prpsinfo_uids(size_t argc, char *argv[], void *data)
{
	struct elf_prpsinfo *p = data;

	if (argc >= 5 && strcmp(argv[0], "Uid:") == 0)
		(void) sscanf(argv[1], sizeof (p->pr_uid) == 2 ? "%hd" : "%d",
		     &p->pr_uid);
	else if (argc >= 5 && strcmp(argv[1], "Gid:") == 0)
		(void) sscanf(argv[1], sizeof (p->pr_gid) == 2 ? "%hd" : "%d",
		     &p->pr_gid);

	return (0);
}

ssize_t
nt_prpsinfo_dump(NElf_Word type, int fd, off_t off, pid_t tid)
{
	struct elf_prpsinfo p;
	ssize_t i, len;

	if (tid != ucore_gettid())
		return (0); /* only for the main thread */

	bzero(&p, sizeof (p));

	(void) ucore_parse(nt_prpsinfo_stat, &p,
	    "/proc/%d/stat", ucore_getpid());

	(void) ucore_parse(nt_prpsinfo_uids, &p,
	    "/proc/%d/status", ucore_getpid());

	(void) ucore_slurp(UCORE_S_STR, p.pr_fname,
	    sizeof (p.pr_fname), "/proc/%d/comm", ucore_getpid());

	len = ucore_slurp(UCORE_S_BIN, p.pr_psargs,
	    sizeof (p.pr_psargs) - 1, "/proc/%d/cmdline", ucore_getpid());

	/*
	 * This loop has an off-by-one error: the final \0 read from cmdline
	 * should be left as-is but is instead blindly turned into a space.
	 * This mimics the observed behavior of Linux-generated core files.
	 */
	for (i = 0; i < len; i++)
		if (p.pr_psargs[i] == '\0')
			p.pr_psargs[i] = ' ';

	return (ucore_note_dump(fd, off, type, "CORE", &p, sizeof (p)));
}
