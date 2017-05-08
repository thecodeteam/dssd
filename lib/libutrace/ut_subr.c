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

#include <utrace_impl.h>

utrace_print_f *UT_printf;
utrace_trace_f *UT_tracef;
FILE *UT_stdout;

void
utrace_redir_print(utrace_print_f *func, FILE *file)
{
	UT_printf = func;
	UT_stdout = file;
}

void
utrace_redir_trace(utrace_trace_f *func)
{
	UT_tracef = func;
}

ssize_t
__attribute__((format(printf, 3, 0)))
utrace_vtracef(char *buf, size_t len, const char *format, va_list ap)
{
	return (UT_tracef(buf, len, format, ap));
}

void
__attribute__((format(printf, 2, 0)))
utrace_vprintf(FILE *fp, const char *format, va_list ap)
{
	(void) UT_printf(fp, format, ap);
}

void
__attribute__((format(printf, 2, 3)))
utrace_printf(FILE *fp, const char *format, ...)
{
	va_list ap;

	va_start(ap, format);
	(void) UT_printf(fp, format, ap);
	va_end(ap);
}

void
__attribute__((format(printf, 1, 2)))
utrace_dprintf(const char *format, ...)
{
	if (yyutdebug) {
		va_list ap;
		va_start(ap, format);
		(void) vfprintf(stderr, format, ap);
		va_end(ap);
	}
}

int
__attribute__((format(printf, 3, 0)))
utrace_verror(utrace_handle_t *uhp, int err, const char *format, va_list ap)
{
	(void) fprintf(stderr, "utrace error: ");
	(void) vfprintf(stderr, format, ap);
	(void) fprintf(stderr, "\n");

	errno = err;
	return (-1);
}

int
__attribute__((format(printf, 3, 4)))
utrace_error(utrace_handle_t *uhp, int err, const char *format, ...)
{
	va_list ap;

	va_start(ap, format);
	err = utrace_verror(uhp, err, format, ap);
	va_end(ap);

	return (err);
}

void *
__attribute__((format(printf, 3, 4)))
utrace_null(utrace_handle_t *uhp, int err, const char *format, ...)
{
	va_list ap;

	va_start(ap, format);
	(void) utrace_verror(uhp, err, format, ap);
	va_end(ap);

	return (NULL);
}
