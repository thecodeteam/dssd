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

#ifndef	_UT_SUBR_H
#define	_UT_SUBR_H

#ifdef	__cplusplus
extern "C" {
#endif

extern ssize_t utrace_vtracef(char *, size_t, const char *, va_list)
    __attribute__((format(printf, 3, 0)));

extern void utrace_vprintf(FILE *, const char *, va_list ap)
    __attribute__((format(printf, 2, 0)));

extern void utrace_printf(FILE *, const char *, ...)
    __attribute__((format(printf, 2, 3)));

extern void utrace_dprintf(const char *, ...)
    __attribute__((format(printf, 1, 2)));

extern int utrace_verror(utrace_handle_t *, int, const char *, va_list)
    __attribute__((format(printf, 3, 0)));

extern int utrace_error(utrace_handle_t *, int, const char *, ...)
    __attribute__((format(printf, 3, 4)));

extern void *utrace_null(utrace_handle_t *, int, const char *, ...)
    __attribute__((format(printf, 3, 4)));

#ifdef	__cplusplus
}
#endif

#endif	/* _UT_SUBR_H */
