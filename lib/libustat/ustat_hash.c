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

#include <errno.h>
#include <pthread.h>
#include <string.h>
#include <stdlib.h>
#include <inttypes.h>

#include <hrtime.h>
#include <ustat_hash.h>
#include <ustat_hash_impl.h>

/*
 * Note: this works well for the objects used so far, but may need to be
 *       passed as a param to ustat_hash_alloc() if future objects don't hash
 *       well with it.
 */
#define OBJ_TO_BUCKET(h, sp) \
    (uint32_t)(((uintptr_t)(sp) >> 3) % h->ush_num_buckets)


/*
 * Allocates and initializes a hash.  ustat_h must stay valid for the duration
 * (until ustat_hash_free() is called and returns).
 */
ustat_hash_t *
ustat_hash_alloc(ustat_handle_t *ustat_h, uint32_t num_buckets,
    const ustat_class_t *sclass)
{
    const size_t total_len = sizeof (ustat_hash_entry_t) * num_buckets;
    ustat_hash_t *h = malloc(sizeof (ustat_hash_t));

    if (h == NULL)
        return (h);

    h->ush_ustat_h = ustat_h;
    (void) pthread_mutex_init(&h->ush_lock, NULL);

    if (total_len >= sizeof (ustat_hash_entry_t)) {
        h->ush_table = malloc(total_len);

        if (h->ush_table == NULL) {
            free(h);
            return (NULL);
        }

        memset(h->ush_table, 0, total_len);
    } else {
        h->ush_table = NULL;
    }

    h->ush_unused = NULL;
    h->ush_num_entries = 0;
    h->ush_num_buckets = num_buckets;
    memcpy(&h->ush_sclass, sclass, sizeof (*sclass));
    return (h);
}


// Walk the hash and call the callback for each populated entry
void
ustat_hash_walk(ustat_hash_t *h, ustat_hash_walk_f cb, void *uval)
{
    ustat_hash_entry_t *hash_e;
    uint32_t i;

    if (h == NULL || h->ush_num_entries == 0)
        return;

    for (i = 0; i < h->ush_num_buckets; ++i) {
        hash_e = &h->ush_table[i];
        do {
            if (hash_e->ushe_obj != NULL &&
              !(cb)(hash_e->ushe_obj, hash_e->ushe_stat, uval))
                return;
            hash_e = hash_e->ushe_next;
        } while (hash_e != NULL);
    }
}


/*
 * Finds an object in the hash and returns its stat pointer.
 * The caller is responsible for ensuring that the ustat entry in question is
 * not freed until after it has finished using it.  Note that this function
 * does not take the ush_lock - it is important for perf. that this runs as
 * fast as possible and doesn't introduce false dependencies (e.g. waiter and
 * poster threads both fighting over the lock).
 */
ustat_struct_t *
ustat_hash_find(const ustat_hash_t *h, const void *obj)
{
    ustat_hash_entry_t *p;

    if (h == NULL || h->ush_num_buckets == 0)
        return (NULL);

    for (p = &h->ush_table[OBJ_TO_BUCKET(h, obj)]; p != NULL;
      p = p->ushe_next) {
        if (p->ushe_obj == obj)
            return (p->ushe_stat);
    }

    return (NULL);
}


static inline ustat_struct_t *
ustat_hash_add_stat_entry(const ustat_hash_t *h, void *obj, const char *ename)
{
    // Create a ustat entry.
    size_t gnamelen;
    char *gname;

    gnamelen = (size_t)snprintf(NULL, 0, "s%" PRIx64, (uint64_t)(uintptr_t)obj);
    gname = alloca(gnamelen + 1);
    (void) snprintf(gname, gnamelen + 1, "s%" PRIx64, (uint64_t)(uintptr_t)obj);

    return (ustat_insert(h->ush_ustat_h, ename, gname, &h->ush_sclass, 0, NULL,
        NULL));
}


/*
 * Adds an object to the hash.
 * ename and obj_name are used in the ustat entries.
 * This is slightly hairy in that ustat_hash_find() is allowed to traverse
 * the hash without taking the lock, so care must be taken to initialize the
 * new entry in the correct order.
 */
ustat_struct_t *
ustat_hash_add(ustat_hash_t *h, void *obj, const char *ename)
{
    ustat_hash_entry_t *p, *new_e;

    if (h == NULL || h->ush_num_buckets == 0 || h->ush_ustat_h == NULL)
        return (NULL);

    (void) pthread_mutex_lock(&h->ush_lock);

    // Search for the object.
    for (p = &h->ush_table[OBJ_TO_BUCKET(h, obj)]; ; p = p->ushe_next) {
        if (p->ushe_obj == obj) {
            goto done;
        } else if (p->ushe_next == NULL) {
            break;
        }
    }

    if (p->ushe_obj != NULL) {
        // Add an overflow entry
        if (h->ush_unused != NULL) {
            new_e = h->ush_unused;
            h->ush_unused = new_e->ushe_next;
        } else {
            new_e = malloc(sizeof (ustat_hash_entry_t));
            if (new_e == NULL) {
                p = NULL;
                goto done;
            }

            new_e->ushe_stat = NULL;
        }

        new_e->ushe_obj = NULL;  // handles ustat_hash_find() access
        new_e->ushe_next = NULL;
        p->ushe_next = new_e;    // now visible to ustat_hash_find()
        p = new_e;
    }

    if (p->ushe_stat == NULL)
        p->ushe_stat = ustat_hash_add_stat_entry(h, obj, ename);

    p->ushe_obj = obj;
    ++h->ush_num_entries;

done:
    (void) pthread_mutex_unlock(&h->ush_lock);
    return (p != NULL ? p->ushe_stat : NULL);
}


/*
 * Removes an object from the hash.  The caller must ensure that no other
 * thread is accessing the hash entry at this time.  ustat_hash_find()
 * calls in particular are dangerous given that the ustat is returned and
 * can be accessed without the lock.
 */
void
ustat_hash_remove(ustat_hash_t *h, void *obj)
{
    ustat_hash_entry_t *p, *prev_p;

    if (h == NULL || h->ush_num_buckets == 0)
        return;

    (void) pthread_mutex_lock(&h->ush_lock);

    p = &h->ush_table[OBJ_TO_BUCKET(h, obj)];

    if (p->ushe_obj != obj) {
        // Move the overflow entry to the unused list
        prev_p = p;
        for (p = p->ushe_next; p != NULL; p = p->ushe_next) {
            if (p->ushe_obj == obj) {
                prev_p->ushe_next = p->ushe_next;
                p->ushe_next = h->ush_unused;
                h->ush_unused = p->ushe_next;
                break;
            }

            prev_p = p;
        }
    }

    if (p != NULL) {
        p->ushe_obj = NULL;
        (void) ustat_delete(p->ushe_stat);
        p->ushe_stat = NULL;
        --h->ush_num_entries;
    }

    (void) pthread_mutex_unlock(&h->ush_lock);
}


// Free a hash entry list
static void
ustat_hash_free_list(ustat_hash_entry_t *l)
{
    ustat_hash_entry_t *e, *next;

    for (e = l; e != NULL; e = next) {
        (void) ustat_delete(e->ushe_stat);
        next = e->ushe_next;
        free(e);
    }
}


// Return the number of used hash entries
uint32_t
ustat_hash_get_nentries(const ustat_hash_t *h)
{
    return (h != NULL ? h->ush_num_entries : 0);
}


/*
 * Free a hash table.  The caller must ensure that no other thread is accessing
 * the hash at this time.  See the comments in ustat_hash_remove() for more info
 */
void
ustat_hash_free(ustat_hash_t *h)
{
    ustat_hash_entry_t *e;
    uint32_t i;

    if (h == NULL)
        return;

    (void) pthread_mutex_lock(&h->ush_lock);

    // Free the hash table entries and overflow buckets
    for (i = 0; i < h->ush_num_buckets; ++i) {
        e = &h->ush_table[i];

        (void) ustat_delete(e->ushe_stat);
        ustat_hash_free_list(e->ushe_next);
    }

    // Free the unused entries
    ustat_hash_free_list(h->ush_unused);
    h->ush_unused = NULL;

    // Free the hash table itself
    free(h->ush_table);
    (void) pthread_mutex_unlock(&h->ush_lock);
    free(h);
}
