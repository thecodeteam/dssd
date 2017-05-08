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

#ifndef USTAT_HASH_IMPL_H
#define USTAT_HASH_IMPL_H

#include <stdint.h>
#include <pthread.h>
#include <ustat.h>


struct ustat_hash_entry
{
    void *ushe_obj;             // hash object
    ustat_struct_t *ushe_stat;  // stats for the hash object
    struct ustat_hash_entry *ushe_next;  // overflow entry
};


// ustat hash table.
struct ustat_hash
{
    ustat_handle_t *ush_ustat_h;
    struct ustat_hash_entry *ush_table;
    struct ustat_hash_entry *ush_unused;  // unused hash entries
    uint32_t ush_num_buckets;
    uint32_t ush_num_entries;
    pthread_mutex_t ush_lock;
    ustat_class_t ush_sclass;  // ustat class for each hash entry's ushe_stat
};


#endif  // USTAT_HASH_IMPL_H
