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
 * UTrace Test Program
 *
 * This program compiles the probe program from stdin, and then calls a stack
 * of three functions, each with a probe defined-- we then use ut_test.u to
 * instrument this sequence and make sure all probes fire, variables trace, etc
 */

#include <utrace.h>
#include <hrtime.h>
#include <pthread.h>
#include <alloca.h>
#include <unistd.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

enum utrace_event {
	EV_FOO,
	EV_BAR,
	EV_BAZ,
};

extern int foo(int);
extern int bar(int);
extern int baz(int);

uint64_t
gethrcycles(void)
{
	return (0xc1c1c1c1c1c1c1c1);
}

uint64_t
gethrtime(void)
{
	return (0xd1d1d1d1d1d1d1d1);
}

int
__attribute__((noinline))
baz(int x)
{
	errno = 123;

	utrace(EV_BAZ, "x=%d", x);

	(void) printf("baz(%d)\n", x);

	return (x + 1);
}

int
__attribute__((noinline))
bar(int x)
{
	utrace(EV_BAR, "x=%d", x);
	x = baz(x + 1);
	return (x + 1);
}

int
__attribute__((noinline))
foo(int x)
{
	utrace(EV_FOO, "x=%d", x);
	x = bar(x + 1);
	return (x + 1);
}

int
main(int argc, char *argv[])
{
	utrace_handle_t *h;
	utrace_request_t *r;

	cpu_set_t *cpus;
	size_t size;
	int rv;
	int x = 1;

	h = utrace_open_self();
	r = utrace_fcompile(h, stdin);

	if (r != NULL)
		utrace_enable(h, r);

	size = CPU_ALLOC_SIZE(sysconf(_SC_NPROCESSORS_CONF));
	cpus = alloca(size);
	CPU_ZERO_S(size, cpus);
	CPU_SET_S(0, size, cpus);
	pthread_setaffinity_np(pthread_self(), size, cpus);

	if (argc > 1) {
		x = atoi(argv[1]);
		while (--x > 0)
			bar(x);
	}

	rv = foo(1);

	utrace_close(h);
	return (rv);
}
