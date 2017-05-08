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

#include <vmem_impl.h>
#include <errno.h>

#define	VMEM_PRINTF_BUF	1024
#define	VMEM_PRINTF_LOG	8192

char vmem_panicstr[VMEM_PRINTF_BUF];
char vmem_printf_log[VMEM_PRINTF_LOG + VMEM_PRINTF_BUF];

/*
 * ============================================================================
 * printf() and panic() routines that don't allocate memory
 * ============================================================================
 */
static void
__attribute__((format(printf, 1, 0)))
vmem_vprintf(const char *fmt, va_list va)
{
	static size_t vmem_printf_log_idx = 0;
	int saved_errno = errno;
	char buf[VMEM_PRINTF_BUF];
	size_t len, idx;

	buf[0] = '\0';
	(void) vsnprintf(buf, sizeof (buf), fmt, va);
	len = strlen(buf);

	idx = __sync_fetch_and_add(&vmem_printf_log_idx, len);
	bcopy(buf, &vmem_printf_log[idx % VMEM_PRINTF_LOG], len);

	(void) write(fileno(stderr), buf, strlen(buf));

	errno = saved_errno;
}

void
__attribute__((format(printf, 1, 2)))
vmem_printf(const char *fmt, ...)
{
	va_list va;

	va_start(va, fmt);
	vmem_vprintf(fmt, va);
	va_end(va);
}

static void
__attribute__((noreturn))
__attribute__((format(printf, 1, 0)))
vmem_vpanic(const char *fmt, va_list va)
{
	int saved_errno = errno;
	static pthread_mutex_t vmem_panic_lock;
	(void) pthread_mutex_lock(&vmem_panic_lock);

	(void) vsnprintf(vmem_panicstr, sizeof (vmem_panicstr) - 1, fmt, va);
	(void) strcat(vmem_panicstr, "\n");
	(void) write(fileno(stderr), vmem_panicstr, strlen(vmem_panicstr));

	errno = saved_errno;
	abort();
}

void
__attribute__((noreturn))
__attribute__((format(printf, 1, 2)))
vmem_panic(const char *fmt, ...)
{
	va_list va;

	va_start(va, fmt);
	vmem_vpanic(fmt, va);
	va_end(va);
}

void
__attribute__((noreturn))
__attribute__((format(printf, 6, 7)))
vmem_panic_xalloc(vmem_t *vm, size_t size, size_t align, size_t phase, int flag,
    const char *fmt, ...)
{
	va_list va;
	char buf[VMEM_PRINTF_BUF];

	(void) snprintf(buf, sizeof (buf), "vmem_xalloc(vm %p = %s, "
	    "size %#zx, align %#zx, phase %#zx, flag %#x): %s",
	    vm, vm->vm_name, size, align, phase, flag, fmt);

	va_start(va, fmt);
	vmem_vpanic(buf, va);
	va_end(va);
}

void
__attribute__((noreturn))
__attribute__((format(printf, 4, 5)))
vmem_panic_free(vmem_t *vm, void *addr, size_t size, const char *fmt, ...)
{
	va_list va;
	char buf[VMEM_PRINTF_BUF];

	(void) snprintf(buf, sizeof (buf),
	    "vmem_free(vm %p = %s, addr %p, size %#zx): %s",
	    vm, vm->vm_name, addr, size, fmt);

	va_start(va, fmt);
	vmem_vpanic(buf, va);
	va_end(va);
}
