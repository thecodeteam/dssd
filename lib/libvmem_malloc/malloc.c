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
#include <stdlib.h>
#include <malloc.h>

#include <vmem.h>

void *
malloc(size_t size)
{
	return (vmem_libc_malloc(size));
}

void *
calloc(size_t nelem, size_t elsize)
{
	return (vmem_libc_calloc(nelem, elsize));
}

void *
memalign(size_t align, size_t size)
{
	return (vmem_libc_memalign(align, size));
}

void *
valloc(size_t size)
{
	return (vmem_libc_valloc(size));
}

void
free(void *buf)
{
	vmem_libc_free(buf);
}

void *
realloc(void *buf, size_t newsize)
{
	return (vmem_libc_realloc(buf, newsize));
}
