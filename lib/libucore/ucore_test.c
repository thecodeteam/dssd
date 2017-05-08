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

#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "ucore.h"

bool ucore_enable = true;
char rodata[16] = "rodata";
char bss[16];
char *heap;
char *stk;

int
main(int argc, char *argv[])
{
	char s[16] = "stack";
	pthread_attr_t attr;
	void *stackaddr;
	size_t stacksize;

	/*
	 * This program reports its stack base and size so that surrounding
	 * test logic will work properly.  See ucore_test.sh.
	 */
	(void) pthread_attr_init(&attr);
	(void) pthread_getattr_np(pthread_self(), &attr);
	(void) pthread_attr_getstack(&attr, &stackaddr, &stacksize);
	(void) pthread_attr_destroy(&attr);
	(void) printf("stackbase=%p\n", stackaddr);
	(void) printf("stacksize=%lu\n", stacksize);
	fflush(stdout);

	(void) strcpy(bss, "bss");
	heap = malloc(16);
	(void) strcpy(heap, "heap");
	stk = s;

	volatile int *p = (int *)0xd5;
	return (*p);
}
