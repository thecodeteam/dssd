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

#ifndef _USTAT_IMPL_H
#define	_USTAT_IMPL_H

#include <pthread.h>
#include <stdint.h>
#include <ustat.h>
#include <list.h>
#include <p2.h>

#ifdef	__cplusplus
extern "C" {
#endif

typedef struct ustat_ifmt {
	const char *usf_i8;
	const char *usf_i16;
	const char *usf_i32;
	const char *usf_i64;
	const char *usf_u8;
	const char *usf_u16;
	const char *usf_u32;
	const char *usf_u64;
	const char *usf_u8_first;
	const char *usf_u8_rest;
	const char *usf_u64_first;
	const char *usf_u64_rest;
} ustat_ifmt_t;

#define	USTAT_MAG0		0x7f
#define	USTAT_MAG1		0x55
#define	USTAT_MAG2		0x53

#define	USTAT_MAG3_32		0x01
#define	USTAT_MAG3_64		0x02
#define	USTAT_MAG3_LE		0x04
#define	USTAT_MAG3_BE		0x08
#define	USTAT_MAG3_ROOT		0x10
#define	USTAT_MAG3_GRP		0x20

#define	USTAT_MAG3_BASE		0x0f
#define	USTAT_MAG3_TYPE		0xf0

#if __BYTE_ORDER == __LITTLE_ENDIAN
#if __WORDSIZE == 64
#define	USTAT_MAG3	(USTAT_MAG3_LE | USTAT_MAG3_64)
#elif __WORDSIZE == 32
#define	USTAT_MAG3	(USTAT_MAG3_LE | USTAT_MAG3_32)
#endif
#elif __BYTE_ORDER == __BIG_ENDIAN
#if __WORDSIZE == 64
#define	USTAT_MAG3	(USTAT_MAG3_BE | USTAT_MAG3_64)
#elif __WORDSIZE == 32
#define	USTAT_MAG3	(USTAT_MAG3_BE | USTAT_MAG3_32)
#endif
#elif __BYTE_ORDER == __BIG_ENDIAN
#endif

typedef struct ustat_page {
	uint8_t usp_magic[4];
	uint32_t usp_size;
	void *usp_addr;
	off_t usp_off;
} ustat_page_t;

typedef struct ustat_group {
	struct ustat_group *usg_next;
	struct ustat_group *usg_prev;
	ustat_handle_t *usg_handle;
	const char *usg_gname;
	const char *usg_cname;
	void *usg_carg;
	void *usg_uarg;
	uint64_t usg_ctime;
	uint64_t usg_atime;
	uint16_t usg_flags;
	uint16_t usg_statc;
	ustat_named_t *usg_statv;
	ustat_value_t *usg_datav;
	char *usg_rodata;
	uint8_t *usg_rwdata;
} ustat_group_t;

/*
 * These structs must be kept in sync with the above native types.
 * They exist to provide a way of importing / exporting ustats
 * between different systems, e.g. 64-bit to 32-bit.
 */
typedef struct ustat_page64 {
	uint8_t usp_magic[4];
	uint32_t usp_size;
	uint64_t usp_addr;
	uint64_t usp_off;
} ustat_page64_t;

typedef struct ustat_group64 {
	uint64_t usg_next;
	uint64_t usg_prev;
	uint64_t usg_handle;
	uint64_t usg_gname;
	uint64_t usg_cname;
	uint64_t usg_carg;
	uint64_t usg_uarg;
	uint64_t usg_ctime;
	uint64_t usg_atime;
	uint16_t usg_flags;
	uint16_t usg_statc;
	uint64_t usg_statv;
	uint64_t usg_datav;
	uint64_t usg_rodata;
	uint64_t usg_rwdata;
} ustat_group64_t;

#define USTAT_DATA_TO_PAGE(h, x) \
    ((ustat_page_t *)P2ALIGN((uintptr_t)x, h->ush_pgsize))

#define USTAT_PAGE_TO_DATA(p) \
    ((void *)P2ROUNDUP((uintptr_t)p + sizeof (ustat_page_t), 16))

#define USTAT_PAGE64_TO_DATA(p) \
    ((uint64_t)P2ROUNDUP((uint64_t)p + sizeof (ustat_page64_t), 16))

#define USTAT_STRUCT_TO_GROUP(s) \
    ((ustat_group_t *)((uintptr_t)s - sizeof (ustat_group_t)))

#define USTAT_GROUP_TO_STRUCT(g) \
    ((ustat_struct_t *)((uintptr_t)g + sizeof (ustat_group_t)))

#define	USTAT_F_INSERTED	0x1	/* ustat_insert() called on me */
#define	USTAT_F_UNLINKED	0x2	/* ustat_unlink() called on me */

typedef struct ustat_root {
	uint32_t usr_gen;
	pid_t usr_pid;
	char *usr_comm;
	char *usr_args;
	ustat_group_t **usr_hash;
	size_t usr_hlen;
} ustat_root_t;

typedef struct ustat_freepage {
	list_node_t usfp_node;
	off_t usfp_off;
	size_t usfp_size;
} ustat_freepage_t;

struct ustat_handle {
	int ush_version;
	int ush_oflags;
	ustat_handle_t *ush_link;
	ustat_root_t *ush_root;
	pthread_rwlock_t ush_lock;
	int (*ush_update)(struct ustat_handle *);
	size_t ush_pgsize;
	char *ush_path;
	int ush_fd;
	size_t ush_fdlen;
	list_t ush_free_pgsz;
	list_t ush_free_other;
	int ush_self;
	int ush_ismem;
};

extern int ustat_set_bson_object(bson_t *b, off_t d, off_t *nd,
    const char *utype, const char *nname);
extern int ustat_add_bson_group(ustat_struct_t *s, bson_t *b, off_t d,
    off_t *nd);
extern int ustat_set_bson_i64(bson_t *b, off_t d, const char *utype,
    const char *nname, int64_t val);
extern int ustat_set_bson_str(bson_t *b, off_t d,
    const char *utype, const char *nname, const char *str);
extern int ustat_set_bson_array(ustat_struct_t *s, bson_t *b, off_t d,
    off_t *nd, const char *utype, const char *nname);

extern int ustat_set_bson_cyctons(ustat_struct_t *s, bson_t *b, off_t d,
    ustat_named_t *n, uint64_t cycle_mult);


#ifdef	__cplusplus
}
#endif

#endif	/* _USTAT_IMPL_H */
