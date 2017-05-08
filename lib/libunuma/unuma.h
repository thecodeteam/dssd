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

#ifndef UNUMA_H
#define UNUMA_H

#include <stdint.h>
#include <stdbool.h>
#include <sys/mman.h>  /* MAP_FAILED */

/*
 * Maximum number of NUMA nodes supported.
 *
 * Do not raise this value unless absolutely necessary - code external to
 * libunuma uses this in ways in which every bit counts.
 */
#define UNUMA_MAX_NODES (8)
#define UNUMA_MAX_SHIFT (3)

/*
 * Default mountpoints for the corresponding hugetlbfs page sizes.
 * These can be overridden by the user.
 */
#if !defined(UNUMA_HUGETLBFS_2M)
#define UNUMA_HUGETLBFS_2M NULL
#endif

#if !defined(UNUMA_HUGETLBFS_1G)
#define UNUMA_HUGETLBFS_1G NULL
#endif

/*
 * Controls whether libunuma is allowed to scan for hugetlbfs mountpoints and
 * use any that match versus only using the default mountpoints, if any, above.
 */
#if !defined(UNUMA_HUGETLBFS_SCAN)
#define UNUMA_HUGETLBFS_SCAN 1
#endif


/*
 * NUMA node page types.
 * UNUMA_PGT_{SMALL,LARGE,HUGE} should be used whenever possible for portability
 */
typedef enum unuma_pgt {
#if defined(__x86_64__)
	UNUMA_PGT_4K,
	UNUMA_PGT_2M,
	UNUMA_PGT_1G,
	UNUMA_PGT_MAX,

	UNUMA_PGT_SMALL = UNUMA_PGT_4K,
	UNUMA_PGT_LARGE = UNUMA_PGT_2M,
	UNUMA_PGT_HUGE  = UNUMA_PGT_1G,
#elif defined(__i386__) || defined(__arm__)
	/* XXX add support for ARM large (64K) pages */
	UNUMA_PGT_4K,
	UNUMA_PGT_MAX,

	UNUMA_PGT_SMALL = UNUMA_PGT_4K,
	UNUMA_PGT_LARGE = UNUMA_PGT_4K,
	UNUMA_PGT_HUGE  = UNUMA_PGT_4K,
#else
#error "unknown arch"
#endif
} unuma_pgt_t;


extern size_t unuma_page_size(unuma_pgt_t);
extern unuma_pgt_t unuma_page_type(uint64_t);

extern int unuma_get_node(void);
extern int unuma_get_nnodes(void);
extern bool unuma_is_node_present(int);
extern uint64_t unuma_node_physmem(int);
extern int64_t unuma_node_pages(unuma_pgt_t, int);
extern int64_t unuma_node_freepages(unuma_pgt_t, int);

extern bool unuma_get_pgt_fallback(void);
extern bool unuma_set_pgt_fallback(bool);
extern bool unuma_is_broken(void);

extern size_t unuma_roundup(size_t, unuma_pgt_t);
extern void *unuma_alloc(void *, size_t, size_t, unuma_pgt_t, int);
extern int unuma_free(void *, size_t);

extern int unuma_vtop(const void *, uint64_t *);
extern int unuma_vtonode(const void *);
extern int unuma_ptonode(uint64_t);

#endif  // UNUMA_H
