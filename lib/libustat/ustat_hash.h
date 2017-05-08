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

#ifndef USTAT_HASH_H
#define USTAT_HASH_H

#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <pthread.h>
#include <ustat.h>

#ifdef  __cplusplus
extern "C" {
#endif

/*
 * The hash walk callback is passed the object and stat for each object,
 * as well as the user-defined value uval passed to ustat_hash_walk().
 * If the callback returns true then continue walking, otherwise stop.
 */
typedef bool (*ustat_hash_walk_f)(void *obj, ustat_struct_t *stats, void *uval);
typedef struct ustat_hash_entry ustat_hash_entry_t;
typedef struct ustat_hash ustat_hash_t;


extern ustat_hash_t *ustat_hash_alloc(ustat_handle_t *ustat_h,
    uint32_t num_buckets, const ustat_class_t *sclass);
extern void ustat_hash_free(ustat_hash_t *h);

// ustat_hash_find() and ustat_hash_walk() do not take the hash lock
extern ustat_struct_t *ustat_hash_find(const ustat_hash_t *h, const void *obj);
extern void ustat_hash_walk(ustat_hash_t *h, ustat_hash_walk_f cb, void *uval);

extern ustat_struct_t *ustat_hash_add(ustat_hash_t *h, void *obj,
    const char *ename);

extern void ustat_hash_remove(ustat_hash_t *h, void *obj);
extern uint32_t ustat_hash_get_nentries(const ustat_hash_t *h);

#ifdef  __cplusplus
}
#endif

#endif  // USTAT_HASH_H
