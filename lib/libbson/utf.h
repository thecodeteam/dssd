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

#ifndef	_UTF_H
#define	_UTF_H

#include <stdint.h>
#include <stdio.h>

#ifdef	__cplusplus
extern "C" {
#endif

extern int unicode_is_sp(uint32_t u);
extern int unicode_is_sp1(uint32_t u1);
extern int unicode_is_sp2(uint32_t u2);
extern void unicode_to_sp(uint32_t u, uint32_t *u1, uint32_t *u2);
extern uint32_t unicode_from_sp(uint32_t u1, uint32_t u2);
extern char *unicode_to_utf8_n(uint32_t u, char *s, int n);
extern const char *unicode_from_utf8_n(uint32_t *u, const char *s, int n);
extern char *unicode_to_utf8(uint32_t u, char *s);
extern const char *unicode_from_utf8(uint32_t *u, const char *s);

#ifdef	__cplusplus
}
#endif

#endif	/* _UTF_H */
