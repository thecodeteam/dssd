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

#ifndef	_UCORE_H
#define	_UCORE_H

#include <stddef.h>
#include <stdbool.h>

#ifdef	__cplusplus
extern "C" {
#endif

typedef void * ucore_handle_t;

extern bool ucore_enable;

extern void ucore_exclude(const void *, size_t);
extern void ucore_include(const void *, size_t);

extern ucore_handle_t ucore_onfault(void (*)(void *), void *);
extern void ucore_nofault(ucore_handle_t);

#ifdef	__cplusplus
}
#endif

#endif	/* _UCORE_H */
