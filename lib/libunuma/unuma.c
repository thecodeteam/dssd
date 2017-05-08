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

/*
 * libunuma
 *
 * 1. Introduction
 *
 * The unuma library provides a user-space library for allocating memory.
 * unuma's chief advantages over a generic allocation API are the ability for
 * the user to specify the MMU page size and NUMA node for the allocation.
 *
 *
 * 2. Interfaces
 *
 * The interfaces exported by libunuma are as follows:
 *
 * unuma_get_node()        - get the NUMA node of the executing thread.
 * unuma_get_nnodes()      - get the #NUMA nodes.
 * unuma_page_size()       - get the page size for a page type.
 * unuma_page_type()       - get the nearest page type for a length.
 * unuma_pages()           - get the total #pages for a page type and node.
 *
 * unuma_node_physmem()    - get the amount of physical memory for a node.
 * unuma_node_freepages()  - get the #free pages for a page type and node.
 *
 * unuma_get_pgt_fallback() - get whether allocations can use smaller pages.
 * unuma_set_pgt_fallback() - set whether allocations can use smaller pages.
 * unuma_is_broken()        - get whether unuma is broken, e.g. buggy mbind()
 *
 * unuma_alloc() - allocate memory.
 * unuma_free()  - free memory.
 *
 * unuma_vtop()     - convert a virtual address to physical address.
 * unuma_vtonode()  - get the NUMA node for a virtual address.
 * unuma_ptonode()  - get the NUMA node for a physical address.
 *
 * Some of the interfaces that take a node accept either a NUMA node# or -1
 * which means "all nodes".  See the documentation for the function in question
 * to check whether it supports -1 for the node#.
 *
 *
 * 3. Implementation.
 *
 * Linux provides multiple ways to allocate huge pages:
 *
 *     1) reserve huge pages via kernel params + mmap() with MAP_HUGETLB
 *
 *     2) reserve huge pages via kernel params + hugetlbfs, optionally via shm
 *        (shmget with SHM_HUGETLB flag)
 *
 *     3) Transparent Huge Page (THP) support.
 *
 * 1) is not an option at this time, since it does not provide a way to specify
 * the huge page size, which is a requirement for libunuma.  A patch has been
 * introduced to the 3.8 kernel which extends mmap()'s interface to allow the
 * page size to be specified, but this is currently later than our minimum
 * supported Linux version.  In the future, once our minimum Linux kernel
 * version includes this patch, libunuma should use this new interface.
 * See https://lwn.net/Articles/533650 for more information.
 *
 * 3) is useless.  THP doesn't have enough information to correctly guess at
 * which ranges of memory should be merged into huge pages, and it is a band-aid
 * that fundamentally works around the original allocations not being made
 * correctly.  In addition, THP causes large application execution delays at
 * random times, i.e. when it decides to merge pages.
 *
 * 2) is libunuma's current implementation.  The number of huge pages for each
 * huge page size is specified on the kernel command line, hugetlbfs is used to
 * access these pages, and mmap() via a temporary hugetlbfs file is used to
 * allocate the pages (shm + SHM_HUGETLB is not used.)
 *
 * The Linux kernel reserves huge pages across all nodes in the system.  For
 * example, if one requested two 1G huge pages on a two-node system, the kernel
 * will reserve one 1G huge page on node 0 and the other on node 1.  The number
 * of huge pages on a given node can be queried via libunuma (see
 * unuma_node_pages() and unuma_node_freepages()).
 *
 * The libunuma implementation is slightly complex in that it has to handle UMA
 * and NUMA systems differently.  In particular, a Linux kernel without NUMA
 * support does not expose the node directories, even for node 0, so the UMA
 * code must query the system-wide memory / huge page directories, whereas the
 * NUMA code must query the node-specific directories for this information.
 *
 * hugetlbfs allocations use a temporary file created under the appropriate
 * filesystem.  This file is immediately unlinked at creation time in order to
 * ensure cleanup on an abnormal application exit.  The hugetlbfs filesystem is
 * chosen by searching for a fixed directory name for a given page size, and
 * falling back to any hugetlbfs filesystem with a matching page size if the
 * default directory name is not found.
 *
 * Huge pages are a scarce global resource, so freeing one is expected to free
 * it back to the O.S.  Using a single file for all allocations of a given page
 * size is not a valid generic solution since the munmap() doesn't actually free
 * the allocation - dropping the refcount on the file's inode, i.e. by
 * munmap()'ing the entire file, is required for _any_ of the pages to be freed.
 *
 * For this reason, groups of huge pages of a given size should be allocated
 * based on when they will be freed.  If all of the huge pages will be used for
 * the life of the application then a single allocation is appropriate in order
 * to reduce the file backing overhead.  Conversely, if some huge pages will be
 * released before the application exits then these should be allocated
 * separately from those that will be used for the entire life of the
 * application so that the former can be freed back to the O.S. early.
 *
 * The virtual to physical address translation functions are only available if
 * the following Linux kernel config option is checked (since this option
 * exposes the system-wide and node memory directories):
 *
 *     Processor type and features -> Allow for memory hot-add
 *
 * which will enable the following config options:
 *
 *     CONFIG_ARCH_MEMORY_PROBE=y
 *     CONFIG_MEMORY_HOTPLUG=y
 *     CONFIG_MEMORY_HOTPLUG_SPARSE=y
 *     CONFIG_ARCH_ENABLE_MEMORY_HOTREMOVE=y
 *
 *
 * 4) Examples
 *
 *     Boot the Linux kernel, specifying the huge pages to reserve:
 *
 *         kernel /boot/vmlinuz hugepagesz=1G hugepages=4 hugepagesz=2M
 *             hugepages=512 default_hugepagesz=2M
 *
 *     Mount the hugetlbfs filesystem(s) in order to expose the above reserved
 *     huge pages to libunuma:
 *
 *         # mount -t hugetlbfs -o pagesize=2M hugetlbfs /mnt/huge-2m
 *         # mount -t hugetlbfs -o pagesize=1G hugetlbfs /mnt/huge-1g
 *         # chmod 777 /mnt/huge-2m /mnt/huge-1g
 *
 *     Allocate pages in one's application via libunuma, e.g.:
 *     (use unuma_node_freepages() first to discover how many pages of a given
 *     size are free on the node, and provide a fallback if the allocation fails
 *     - there is an implicit race condition between the read of
 *     unuma_node_freepages() and unuma_alloc() since these are global
 *     resources.)
 *
 *         int n = unuma_get_node();
 *
 *         void *v4m = unuma_alloc(NULL, 4 * 1024 * 1024, UNUMA_PGT_LARGE, n);
 *
 *         void *v1g = unuma_alloc(NULL, 1024 * 1024 * 1024, UNUMA_PGT_HUGE, n);
 *
 *     Note the use of UNUMA_PGT_{SMALL,LARGE,HUGE}, which is preferable for
 *     portability reasons over the explicit-sized versions (UNUMA_PGT_4K etc.)
 *
 *     libunuma also provides a way to query the nearest page size for a length,
 *     e.g.:
 *
 *         uint64_t len = 3 * 1024 * 1024;
 *
 *         void *v = unuma_alloc(NULL, len, unuma_page_type(len), node);
 *
 *     For x86-64, the above would attempt to allocate the 3MB using two 2MB
 *     huge pages, since the 2MB page size is closer to 'length' than the 1GB
 *     page size.
 *
 *     unuma_page_type() will likely be a good solution in general, although
 *     there will be times when it will be better to trade memory for TLB hits:
 *     unuma_page_type() does the opposite in that it favors memory over TLB
 *     entries.
 *
 *     To ensure that the page sizes requested were actually allocated, one can
 *     look at /proc/{pid}/smaps, e.g.:
 *
 *         7fbdc0000000-7fbec0000000 rw-s 00000000 00:22 148416
 *             /mnt/huge-1g/unuma.31960.31960 (deleted)
 *         Size:            4194304 kB
 *         ...
 *         MMUPageSize:     1048576 kB
 */

#define _LARGEFILE64_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/utsname.h>
#include <fcntl.h>
#include <asm-generic/mman.h>
#include <dirent.h>
#include <errno.h>
#include <ctype.h>
#include <linux/mempolicy.h>  /* for MPOL_BIND */

#include <atomic.h>
#include <units.h>
#include <unuma.h>
#include <p2.h>

#if defined(__x86_64__)
#include <x86intrin.h>  /* __rdtscp() */
#endif

/* Define UNUMA_getcpu(cpu, node) to the supported getcpu() implementation */
#if defined(SYS_getcpu)
/* This is the usual syscall name */
#define UNUMA_getcpu(cpu, node) syscall(SYS_getcpu, cpu, node, NULL)
#elif defined(SYS_get_cpu)
/* EL6 defines SYS_get_cpu for x86-64 only */
#define UNUMA_getcpu(cpu, node) syscall(SYS_get_cpu, cpu, node, NULL)
#elif defined(__x86_64__)
/* SLES uses the vsyscall interface for x86 */
#include <asm/vsyscall.h>
#if defined(VSYSCALL_ADDR)
/* Note: there is no getcpu_cache param for the vsyscall version */
typedef long (*unuma_vgetcpu_f)(unsigned *, unsigned *);
#define UNUMA_getcpu(cpu, node) \
	((unuma_vgetcpu_f)VSYSCALL_ADDR(__NR_vgetcpu))(cpu, node)
#endif  /* VSYSCALL_ADDR */
#endif  /* SYS_getcpu */

#if !defined(UNUMA_getcpu)
#error no getcpu implementation found
#endif


/* pagemap definitions.  See: Documentation/vm/pagemap.txt */
#define PMAP_PRESENT 0x8000000000000000ULL
#define PMAP_FRAME   0x7fffffffffffffULL
#define PMAP_SMASK   0x1f80000000000000ULL
#define PMAP_SOFF    55


/* unuma spinlock */
typedef struct unuma_lock_s {
	uint64_t unl_lock;
} __attribute__ ((aligned (64))) unuma_lock_t;


/* NUMA node page type bitflags */
typedef enum unuma_pgt_flags {
	UNUMA_PGTF_NONE = 0x00,      /* no flags */
	UNUMA_PGTF_HUGETLBFS = 0x01, /* pages must be hugetlbfs allocated */
} unuma_pgt_flags_t;


/* NUMA node page type attributes */
typedef struct unuma_pgt_attr {
	size_t upa_pgsz;              /* page size in bytes */
	int upa_pgt_flags;            /* page type flags */
	const char *upa_default_mnt;  /* default mountpoint or NULL */
	int upa_mnt_fd;               /* file descriptor for mountpoint */
} unuma_pgt_attr_t;


/* NUMA node page type attributes */
static unuma_pgt_attr_t unuma_pgt_attrs[UNUMA_PGT_MAX] = {
#if defined(__x86_64__)
	{ 4 * U_KB, UNUMA_PGTF_NONE, NULL, -1 },
	{ 2 * U_MB, UNUMA_PGTF_HUGETLBFS, UNUMA_HUGETLBFS_2M, -1 },
	{ 1 * U_GB, UNUMA_PGTF_HUGETLBFS, UNUMA_HUGETLBFS_1G, -1 },
#elif defined(__i386__) || defined(__arm__)
	{ 4 * U_KB, UNUMA_PGTF_NONE, NULL, -1 },
#else
#error "unknown arch"
#endif
};


/*
 * Contiguous memory range - either physical or virtual.
 *
 * Note: defined as a uint64_t instead of a ptr to support > word size memory,
 * e.g. x86-32 on x86-64, x86-32 with PAE etc.
 */
typedef struct unuma_mrange {
	uint64_t umr_start;  /* start address */
	uint64_t umr_len;    /* length in bytes */
} unuma_mrange_t;


/* NUMA node info */
typedef struct unuma_info {
	int uni_node;                        /* NUMA node# */
	int uni_npranges;                    /* #ranges in uni_pranges */
	int64_t uni_tpages[UNUMA_PGT_MAX];   /* total #pages or -1 if unknown */
	unuma_mrange_t *uni_pranges;         /* physical address ranges */
	size_t uni_prange_alen;              /* uni_pranges alloc length */
	bool present;                        /* is this NUMA node present */
} unuma_info_t;


/* NUMA node info for all nodes */
typedef struct unuma_nodes {
	int unn_nnodes;                          /* #NUMA nodes, or -1 */
	int unn_zero_fd;                         /* /dev/zero fd */
	int unn_pmap_fd;                         /* pagemap fd */
	int unn_has_node_dir;                    /* does unuma_node_dir exist */
	uint64_t unn_physmem_blksz;              /* mem block size in bytes */
	unuma_info_t unn_info[UNUMA_MAX_NODES];  /* node-specific info */
	unuma_lock_t unn_locks[UNUMA_MAX_NODES][UNUMA_PGT_MAX]; /* page locks */
} unuma_nodes_t;


typedef int unuma_get_node_f(void);


/*
 * /sys directory names:
 *
 *     unuma_shuge_dir: system-wide hugepage directory name.
 *     unuma_smem_dir:  system-wide memory directory name.
 *     unuma_node_dir:  node directory name.
 */
static const char *unuma_shuge_dir = "/sys/kernel/mm/hugepages";
static const char *unuma_smem_dir = "/sys/devices/system/memory";
static const char *unuma_node_dir = "/sys/devices/system/node";
static const char *unuma_vendor_file = "/sys/devices/virtual/dmi/id/sys_vendor";

static unuma_nodes_t unuma_nodes;  /* the NUMA node state */
static bool unuma_pgt_fallback = true;  /* allow smaller pgt allocations */
static bool unuma_enable_mbind = false;  /* allow calls to mbind() */
static int unuma_get_node_syscall(void);

/* Pointer to the active 'get node#' implementation */
static unuma_get_node_f *unuma_get_node_funcp = unuma_get_node_syscall;


/**
 * unuma_getline() reads a line from a stream, allocating memory if necessary.
 * This function is identical to glibc's getline() except that it uses mmap()
 * instead of malloc() since the memory system may be uninitialized.
 * The user program is responsible for freeing *lineptr via munmap().
 *
 * @param [inout] lineptr	- line to be read.
 * @param [inout] n		- allocation size of the line in bytes.
 * @param [inout] stream	- stream to be read from.
 *
 * @return	number of bytes read, -1 on EOF/error.
 *
 * @see		getline()
 */
static ssize_t
unuma_getline(char **lineptr, size_t *n, FILE *stream)
{
	int prot = PROT_READ | PROT_WRITE;
	int flags = MAP_PRIVATE | MAP_ANONYMOUS;
	char *line = *lineptr;
	size_t alen = *n;
	size_t olen, len = 0;

	if (line == NULL || alen == 0) {
		alen = getpagesize();
		if ((line = mmap(NULL, alen, prot, flags, -1, 0)) == MAP_FAILED)
			return (-1);
		*lineptr = line;
		*n = alen;
	}

	line[0] = '\0';
	while (fgets(&line[len], alen - len, stream) != NULL) {
		if ((len = strlen(line)) == 0)
			break;

		if (line[len - 1] == '\r' || line[len - 1] == '\n')
			return (len);

		/* realloc */
		olen = alen;
		alen *= 2;
		if ((line = mmap(NULL, alen, prot, flags, -1, 0)) == MAP_FAILED)
			return (-1);

		(void) strcpy(line, *lineptr);
		(void) munmap(*lineptr, olen);
		*lineptr = line;
		*n = alen;
	}

	return (-1);
}


/**
 * unuma_str2size64() converts a string containing a uint64 plus an optional
 * size specifier to a uint64_t.
 *
 * @param [in] s	- string containing the value.
 * @param [out] vp	- value.
 *
 * @return	0 on success, errno on error.
 */
static int
unuma_str2size64(const char *s, uint64_t *vp)
{
	const char units[] = "BKMGTPE";

	char *q;
	uint64_t v;

	errno = 0;
	v = strtoull(s, &q, 0);

	if (errno == ERANGE)
		return (errno);

	if (errno != 0 || q == s || *s == '-')
		return (errno ? errno : EINVAL);

	if (*q != '\0') {
		const char *u;
		size_t shift;

		if ((u = strchr(units, toupper(*q))) == NULL)
			goto done;

		shift = 10 * (u - units);

		if (v > (UINT64_MAX >> shift))
			return (ERANGE);

		v <<= shift;
	}

done:
	if (vp != NULL)
		*vp = v;

	return (0);
}


/**
 * unuma_read_uint64_file() reads a file, which is expected to contain a single
 * uint64 value in base 'base', and sets 'value'.
 *
 * @param [in] dname	- directory name containing fname.
 * @param [in] fname	- filename.
 * @param [in] base	- base of value stored in file.
 * @param [out] value	- pointer to resulting value.
 *
 * @return	0 on success, -1 on error.
 */
static int
unuma_read_uint64_file(const char *dname, const char *fname, int base,
    uint64_t *value)
{
	char buf[256];  /* uint64_t string in 'base' + null term */
	ssize_t bread = -1;
	int dlen, fd;
	char *pname;

	dlen = snprintf(NULL, 0, "%s/%s", dname, fname) + 1;
	pname = alloca(dlen);
	(void) snprintf(pname, dlen, "%s/%s", dname, fname);

	if ((fd = open(pname, O_RDONLY)) != -1) {
		bread = read(fd, buf, sizeof (buf) - 1);

		if (bread >= 0)
			*(buf + bread) = '\0';

		(void) close(fd);
	}

	if (bread > 0) {
		*value = (uint64_t)strtoull(buf, NULL, base);
		return (0);
	}

	return (-1);
}


/**
 * unuma_get_hugepage_dir() gets the hugepage directory for the page type and
 * node.
 *
 * There is a system-wide hugepage directory, as well as per-node hugepage
 * directories - the latter will only exist if NUMA has been enabled in the
 * kernel.  If dname is NULL then this returns the number of bytes required to
 * store the directory name.
 *
 * @param [out] dname	- huge page directory name.
 * @param [in] dlen	- length of dname in bytes.
 * @param [in] pgt	- page type.
 * @param [in] node	- NUMA node#.
 *
 * @return	length written.
 */
static int
unuma_get_hugepage_dir(char *dname, size_t dlen, unuma_pgt_t pgt, int node)
{
	uint64_t pgkB = unuma_page_size(pgt) / 1024;

	if (unuma_nodes.unn_has_node_dir == 1)
		return (snprintf(dname, dlen,
		    "%s/node%d/hugepages/hugepages-%jukB",
		    unuma_node_dir, node, pgkB));

	if (node <= 0 && unuma_get_nnodes() == 1)
		return (snprintf(dname, dlen, "%s/hugepages-%jukB",
		    unuma_shuge_dir, pgkB));

	if (dlen > 0)
		dname[0] = '\0';

	return (0);
}


/**
 * unuma_get_physmem_dir() gets the physical memory directory for the node.
 *
 * There is a system-wide memory directory, as well as per-node memory
 * directories - the latter will only exist if NUMA has been enabled in the
 * kernel.  If dname is NULL then this returns the number of bytes required to
 * store the directory name.
 *
 * @param [out] dname	- huge page directory name.
 * @param [in] dlen	- length of dname in bytes.
 * @param [in] node	- NUMA node#.
 *
 * @return	length written.
 */
static int
unuma_get_physmem_dir(char *dname, size_t dlen, int node)
{
	if (unuma_nodes.unn_has_node_dir == 1)
		return (snprintf(dname, dlen, "%s/node%d", unuma_node_dir,
		    node));

	if (node <= 0 && unuma_get_nnodes() == 1)
		return (snprintf(dname, dlen, "%s", unuma_smem_dir));

	if (dlen > 0)
		dname[0] = '\0';

	return (0);
}


/**
 * unuma_get_mrange() populates 'mrange' with the memory range for physical
 * memory block 'n'.
 *
 * @param [out] mrange	- pointer to memory range to be populated.
 * @param [in] n	- memory block#.
 *
 * @return	0 on success, -1 on failure.
 *
 * @see		unuma_init_physmem()
 */
static int
unuma_get_mrange(unuma_mrange_t *mrange, int n)
{
	uint64_t blksz = unuma_nodes.unn_physmem_blksz;
	uint64_t phys_index, end_phys_index;
	char *dname;
	int dlen;

	dlen = snprintf(NULL, 0, "%s/memory%d", unuma_smem_dir, n) + 1;
	dname = alloca(dlen);
	(void) snprintf(dname, dlen, "%s/memory%d", unuma_smem_dir, n);

	if (unuma_read_uint64_file(dname, "phys_index", 16, &phys_index) != 0)
		return (-1);

	if (unuma_read_uint64_file(dname, "end_phys_index", 16, &end_phys_index)
	    != 0)
		return (-1);

	mrange->umr_start = phys_index * blksz;
	mrange->umr_len = ((end_phys_index + 1) * blksz) - mrange->umr_start;
	return (0);
}


/**
 * unuma_sort_mranges() is a qsort callback to sort memory ranges based on the
 * start address.
 *
 * @param [in] p1	- pointer to the first memory range.
 * @param [in] p2	- pointer to the second memory range.
 *
 * @return	-1 on less than, 0 on equal, +1 on greater than.
 *
 * @see		unuma_init_physmem()
 */
static int
unuma_sort_mranges(const void *p1, const void *p2)
{
	const unuma_mrange_t *m1 = p1;
	const unuma_mrange_t *m2 = p2;

	if (m1->umr_start < m2->umr_start)
		return (-1);
	else if (m1->umr_start > m2->umr_start)
		return (1);

	return (0);
}


/**
 * unuma_init_physmem() initializes the physical memory range info for the node.
 *
 * @param [in] node	- NUMA node.
 *
 * @return	0 on success, -1 on failure.
 *
 * @see		unuma_init_node(), unuma_init_pgt_info()
 */
static int
unuma_init_physmem(int node)
{
	unuma_info_t *n = &unuma_nodes.unn_info[node];
	unuma_mrange_t *mranges, *srange, *drange;
	int memn, nblks, nused = 0, ret = 0;
	unuma_pgt_t pgt = UNUMA_PGT_SMALL;
	struct dirent en, *res;
	size_t nbytes;
	char *dname;
	int dlen;
	DIR *dp;

	if ((dlen = unuma_get_physmem_dir(NULL, 0, node)) == 0)
		return (-1);

	dlen++;
	dname = alloca(dlen);
	(void) unuma_get_physmem_dir(dname, dlen, node);

	if ((dp = opendir(dname)) == NULL)
		return (-1);

	/* get the #memory blocks and alloc temp space */
	for (nblks = 0; readdir_r(dp, &en, &res) == 0 && res != NULL; )
		if (strncmp(en.d_name, "memory", 6) == 0)
			++nblks;

	if (nblks == 0)
		goto done;

	mranges = alloca(sizeof (unuma_mrange_t) * nblks);

	/* get the memory block ranges */
	rewinddir(dp);
	while (readdir_r(dp, &en, &res) == 0 && res != NULL && nused < nblks) {
		if (strncmp(en.d_name, "memory", 6) == 0) {
			errno = 0;
			memn = strtol(en.d_name + 6, NULL, 10);
			if (errno != 0 || memn < 0)
				continue;

			ret = unuma_get_mrange(&mranges[nused], memn);
			if (ret == 0)
				++nused;
			else {
				ret = -1;
				goto done;
			}
		}
	}

	/* merge the blocks */
	qsort(mranges, nused, sizeof (unuma_mrange_t), unuma_sort_mranges);

	drange = mranges;
	for (srange = &mranges[1]; srange < &mranges[nused]; srange++)
		if (drange->umr_start + drange->umr_len == srange->umr_start)
			drange->umr_len += srange->umr_len;
		else if (++drange != srange)
			*drange = *srange;

	n->uni_npranges = drange - mranges + 1;
	nbytes = sizeof (unuma_mrange_t) * n->uni_npranges;
	n->uni_prange_alen = unuma_roundup(nbytes, pgt);
	n->uni_pranges = unuma_alloc(NULL, n->uni_prange_alen, 0, pgt, node);

	if (n->uni_pranges != MAP_FAILED)
		(void) memcpy(n->uni_pranges, mranges, nbytes);
	else {
		n->uni_prange_alen = 0;
		n->uni_npranges = 0;
		ret = -1;
	}

done:
	(void) closedir(dp);
	return (ret);
}


/**
 * unuma_init_pgt_info() initializes the page type info for the node.
 *
 * @param [in] node	- NUMA node.
 *
 * @see		unuma_init_node(), unuma_init_physmem()
 */
static void
unuma_init_pgt_info(int node)
{
	unuma_info_t *n = &unuma_nodes.unn_info[node];
	const unuma_pgt_attr_t *pattr;
	int dlen;

	for (unuma_pgt_t pgt = 0; pgt < UNUMA_PGT_MAX; pgt++) {
		char *dname;

		pattr = &unuma_pgt_attrs[pgt];
		n->uni_tpages[pgt] = -1;

		if ((pattr->upa_pgt_flags & UNUMA_PGTF_HUGETLBFS) != 0 &&
		    pattr->upa_mnt_fd == -1) {
			/* hide inaccessible huge pages */
			n->uni_tpages[pgt] = 0;
			continue;
		}

		if ((dlen = unuma_get_hugepage_dir(NULL, 0, pgt, node)) == 0)
			continue;

		dlen++;
		dname = alloca(dlen);
		(void) unuma_get_hugepage_dir(dname, dlen, pgt, node);

		(void) unuma_read_uint64_file(dname, "nr_hugepages", 10,
		    (uint64_t *)&n->uni_tpages[pgt]);
	}
}


/**
 * unuma_create_file_backing() creates a file backing for mmap() calls.
 * The file is unlinked at creation time.
 *
 * @param [in] dir_fd	- file descriptor of the dir. to create the file in.
 *
 * @return	file descriptor on success, -1 and errno on failure.
 *
 * @see		unuma_open_pgsz_mount(), unuma_open_page_mounts()
 */
static int
unuma_create_file_backing(int dir_fd)
{
	int flags = O_CREAT | O_EXCL | O_LARGEFILE | O_RDWR;
	pid_t pid = getpid();
	pid_t tid = syscall(SYS_gettid);
	char *fname;
	int flen, fd;

	flen = snprintf(NULL, 0, "unuma.%d.%d", pid, tid) + 1;
	fname = alloca(flen);
	(void) snprintf(fname, flen, "unuma.%d.%d", pid, tid);

	if ((fd = openat(dir_fd, fname, flags, S_IRWXU)) == -1)
		return (-1);

	if (unlinkat(dir_fd, fname, 0) != 0) {
		(void) close(fd);
		return (-1);
	}

	return (fd);
}


/**
 * unuma_open_pgsz_mount() opens a mountpoint for the page size.
 *
 * @param [in] pgt	- page type to use.
 * @param [in] mntpoint	- preferred mountpoint, or NULL to use the first found.
 *
 * @return	file descriptor of mountpoint on success, -1 on failure.
 *
 * @see		unuma_create_file_backing(), unuma_open_page_mounts()
 */
static int
unuma_open_pgsz_mount(unuma_pgt_t pgt, const char *mntpoint)
{
	uint64_t pgsz = unuma_pgt_attrs[pgt].upa_pgsz;
	const char *ldelim = " ";  /* mounts line delimeter */
	const char *odelim = ",";  /* mounts opts delimeter */
	char *op, *oq, *opts;
	char *lp, *lq, *mnt;
	char *line = NULL;
	FILE *mfp = NULL;
	size_t alen = 0;
	uint64_t mpgsz;
	int fd = -1;

	if ((mfp = fopen("/proc/self/mounts", "r")) == NULL)
		return (fd);

	while (unuma_getline(&line, &alen, mfp) > 0) {
		/* search for: hugetlbfs {mntpoint} hugetlbfs {opts} ... */
		if ((lp = strtok_r(line, ldelim, &lq)) == NULL ||
		    strcmp(lp, "hugetlbfs") != 0 ||
		    (mnt = strtok_r(NULL, ldelim, &lq)) == NULL ||
		    strtok_r(NULL, ldelim, &lq) == NULL ||
		    (opts = strtok_r(NULL, ldelim, &lq)) == NULL)
			continue;

		/* make sure the mountpoint, if any, matches */
		if (mntpoint != NULL && strcmp(mntpoint, mnt) != 0)
			continue;

		/* search the opts for the pagesize */
		for (op = strtok_r(opts, odelim, &oq); op != NULL;
		    op = strtok_r(NULL, odelim, &oq)) {
			if (strncmp(op, "pagesize=", 9) != 0 ||
			    unuma_str2size64(op + 9, &mpgsz) != 0)
				continue;

			if (pgsz != mpgsz)
				break;

			if ((fd = open(mnt, O_RDONLY)) != -1)
				goto done;
		}
	}

done:
	if (mfp != NULL)
		(void) fclose(mfp);

	if (line != NULL)
		(void) munmap(line, alen);

	return (fd);
}


/**
 * unuma_open_page_mounts() finds a mountpoint for each page size and opens a
 * fd against each so that allocations can be made.
 *
 * @see		unuma_open_pgsz_mount()
 */
static void
unuma_open_page_mounts(void)
{
	unuma_pgt_attr_t *pattr;
	const char *mnt;
	int fd;

	for (unuma_pgt_t pgt = 0; pgt < UNUMA_PGT_MAX; pgt++) {
		pattr = &unuma_pgt_attrs[pgt];
		fd = pattr->upa_mnt_fd;

		if (fd != -1 || (pattr->upa_pgt_flags & UNUMA_PGTF_HUGETLBFS)
		    == 0)
			continue;

		/* try the default mountpoint, if any */
		if ((mnt = unuma_pgt_attrs[pgt].upa_default_mnt) != NULL)
			fd = unuma_open_pgsz_mount(pgt, mnt);

#if (UNUMA_HUGETLBFS_SCAN == 1)
		/* fallback to any matching mountpoint */
		if (fd == -1)
			fd = unuma_open_pgsz_mount(pgt, NULL);
#endif

		pattr->upa_mnt_fd = fd;
	}
}


/**
 * unuma_init_node() initializes a NUMA node.
 *
 * @param [in] node	- NUMA node.
 *
 * @see		unuma_init()
 */
static void
unuma_init_node(int node)
{
	unuma_nodes.unn_info[node].present = true;

	if (node + 1 > unuma_nodes.unn_nnodes)
		unuma_nodes.unn_nnodes = node + 1;

	(void) unuma_init_physmem(node);
	unuma_init_pgt_info(node);
}


#if defined(__x86_64__)

/* RDTSCP version of unuma_get_node(): faster than the syscall version. */
static int
unuma_get_node_rdtscp(void)
{
	unsigned cpu, node;

	/* See vsyscall_64.c:vgetcpu() for the implementation. */
	(void) __rdtscp(&cpu);
	node = (cpu >> 12) & 0xff;

	return (node);
}


/**
 * unuma_set_get_node() sets the implementation of the unuma_get_node()
 * function.  Passing NULL sets the default implementation.
 *
 * @see         cpuid_get_num_cpus()
 */
static void
unuma_set_get_node(unuma_get_node_f *f)
{
	unuma_get_node_funcp = (f != NULL ? f : unuma_get_node_syscall);
}

#endif /* defined(__x86_64__) */


/* syscall version of unuma_get_node() */
static int
unuma_get_node_syscall(void)
{
	unsigned cpu, node;

	if (UNUMA_getcpu(&cpu, &node) != 0)
		return (-1);

	return (node);
}


/**
 * unuma_get_node() returns the NUMA node number of the executing thread
 * at the time of calling.
 *
 * @return	NUMA node# on success, -1 on failure.
 *
 * @see		unuma_get_nnodes()
 */
int
unuma_get_node(void)
{
	return ((*unuma_get_node_funcp)());
}


/**
 * unuma_get_nnodes() returns the number of NUMA nodes in the system.
 *
 * UMA systems are considered to have 1 NUMA node.
 *
 * Noncontiguous NUMA node systems are considered to have max(NUMA node#) nodes.
 *
 * Systems with max(NUMA node#) >= UNUMA_MAX_NODES are not supported by
 * libunuma, and unuma_get_nnodes() returns -1 in this case.
 *
 * @return	number of NUMA nodes, or -1 if the system is not supported.
 *
 * @see		unuma_get_node(), unuma_is_node_present()
 */
int
unuma_get_nnodes(void)
{
	return (unuma_nodes.unn_nnodes);
}


/**
 * unuma_is_node_present() checks whether the NUMA node exists in the system.
 *
 * @return	true or false depending on whether the NUMA node is present or
 *		not.
 *
 * @see		unuma_get_nnodes()
 */
bool
unuma_is_node_present(int node)
{
	if (node >= 0 && node < unuma_get_nnodes())
		return (unuma_nodes.unn_info[node].present);

	return (false);
}


/**
 * unuma_node_physmem() returns the amount of physical memory in bytes for the
 * node(s).
 *
 * @param [in] node	- NUMA node#, or -1 for all nodes.
 *
 * @return	amount of physical memory in bytes for the node(s).
 *
 * @see		unuma_page_size()
 */
uint64_t
unuma_node_physmem(int node)
{
	int nnodes = unuma_get_nnodes();
	uint64_t nbytes = 0;
	unuma_info_t *n;

	for (int i = 0; i < nnodes; i++) {
		if (i != node && node != -1)
			continue;

		n = &unuma_nodes.unn_info[i];

		for (int pr = 0; pr < n->uni_npranges; pr++)
			nbytes += n->uni_pranges[pr].umr_len;
	}

	return (nbytes);
}


/**
 * unuma_page_size() returns the page size in bytes for the page type.
 *
 * @param [in] pgt	- page type.
 *
 * @return	page size in bytes for the page type, or 0 if invalid.
 *
 * @see		unuma_node_physmem(), unuma_node_pages()
 */
size_t
unuma_page_size(unuma_pgt_t pgt)
{
	if (pgt >= UNUMA_PGT_MAX)
		return (0);

	return (unuma_pgt_attrs[pgt].upa_pgsz);
}


/**
 * unuma_page_type() returns the nearest page type for the length.
 *
 * This function aims to reduce wasted memory at the expense of extra TLB
 * entries, i.e. rounds down to the nearest page size instead of rounding up to
 * the next largest page size.
 *
 * @param [in] length	- length in bytes.
 *
 * @return	page type.
 *
 * @see		unuma_page_size()
 */
unuma_pgt_t
unuma_page_type(uint64_t length)
{
	uint64_t pgsz, next_pgsz;

	for (unuma_pgt_t pgt = 0; pgt < UNUMA_PGT_MAX; pgt++) {
		pgsz = unuma_pgt_attrs[pgt].upa_pgsz;

		if (pgsz >= length) {
			return (pgt);
		} else if (pgt + 1 < UNUMA_PGT_MAX) {
			next_pgsz = unuma_pgt_attrs[pgt + 1].upa_pgsz;

			if (next_pgsz > length &&
			    length - pgsz <= next_pgsz - length)
				return (pgt);
		}
	}

	return (UNUMA_PGT_MAX - 1);
}


/**
 * unuma_node_pages() returns the total number of pages for the node(s) page
 * type.
 *
 * @param [in] pgt	- page type.
 * @param [in] node	- NUMA node#, or -1 for all nodes.
 *
 * @return	total number of pages for the node(s)' page type, -1 if unknown.
 *
 * @see		unuma_node_physmem(), unuma_page_size()
 */
int64_t
unuma_node_pages(unuma_pgt_t pgt, int node)
{
	int nnodes = unuma_get_nnodes();
	int64_t npages = 0;
	unuma_info_t *n;

	if (pgt >= UNUMA_PGT_MAX)
		return (-1);

	for (int i = 0; i < nnodes; i++) {
		if (i != node && node != -1)
			continue;

		n = &unuma_nodes.unn_info[i];

		if (n->uni_tpages[pgt] == -1)
			return (-1);
		else
			npages += n->uni_tpages[pgt];
	}

	return (npages);
}


/**
 * unuma_node_freepages() returns the number of free pages for the node(s) page
 * type.
 *
 * @param [in] pgt	- page type.
 * @param [in] node	- NUMA node#, or -1 for all nodes.
 *
 * @return	number of free pages for the node(s)' page type, -1 if unknown.
 *
 * @see		unuma_node_pages(), unuma_page_size()
 */
int64_t
unuma_node_freepages(unuma_pgt_t pgt, int node)
{
	const unuma_pgt_attr_t *pattr = &unuma_pgt_attrs[pgt];
	int nnodes = unuma_get_nnodes();
	unuma_info_t *ninfo;
	int64_t tfree = 0;
	uint64_t nfree;
	int dlen;

	if (pgt >= UNUMA_PGT_MAX)
		return (-1);

	for (int i = 0; i < nnodes; i++) {
		char *dname;

		if (i != node && node != -1)
			continue;

		ninfo = &unuma_nodes.unn_info[i];
		if ((pattr->upa_pgt_flags & UNUMA_PGTF_HUGETLBFS) != 0 &&
		    ninfo->uni_tpages[pgt] == 0) {
			/* hide inaccessible huge pages */
			continue;
		}

		if ((dlen = unuma_get_hugepage_dir(NULL, 0, pgt, i)) == 0)
			return (-1);

		dlen++;
		dname = alloca(dlen);
		(void) unuma_get_hugepage_dir(dname, dlen, pgt, i);

		if (unuma_read_uint64_file(dname, "free_hugepages", 10, &nfree)
		    == 0)
			tfree += nfree;
		else
			return (-1);
	}

	return (tfree);
}


/**
 * unuma_get_pgt_fallback() returns whether unuma allocations for the process
 * are allowed to fall back to smaller page types if there are no available
 * pages of the requested page type.
 *
 * @return	the fallback setting.
 *
 * @see		unuma_set_pgt_fallback(), unuma_alloc()
 */
bool
unuma_get_pgt_fallback(void)
{
	return (unuma_pgt_fallback);
}


/**
 * unuma_set_pgt_fallback() sets whether unuma allocations for the process are
 * allowed to fall back to smaller page types if there are no available pages of
 * the requested page type.
 *
 * @param [in] fallback	- enable/disable falling back to a smaller page type.
 *
 * @return	the old fallback setting.
 *
 * @see		unuma_get_pgt_fallback(), unuma_alloc()
 */
bool
unuma_set_pgt_fallback(bool fallback)
{
	bool old_fallback = unuma_pgt_fallback;

	unuma_pgt_fallback = fallback;
	return (old_fallback);
}


/**
 * unuma_is_broken() returns whether the NUMA functionality of libunuma is
 * broken or not, e.g. due to a buggy mbind().  It is still safe to use libunuma
 * to allocate memory in the broken case - the memory is just not guaranteed to
 * be allocated on the requested node(s).
 *
 * mbind() is broken on some versions of Linux, and calling the broken version
 * results in pages of memory being unmapped at random times.  Multiple patches
 * are involved in breaking / fixing mbind(), but the latest fix is:
 *
 *     https://lkml.org/lkml/2013/8/16/430
 *
 * libunuma will not call mbind() if this syscall is broken, which will result
 * in libunuma failing to allocate memory on the specified node.  Put another
 * way: a broken mbind() means broken NUMA.  Under the broken kernels, any
 * application that calls mbind() is susceptible to crashing.  It is highly
 * recommended for both stability and performance that one immediately update
 * one's kernel to a version that does not have this bug.
 *
 * The latest fix for mbind() (the patch mentioned in the above URL) was first
 * applied in Linux 3.10.5.
 *
 * @return	true = NUMA is broken, false = NUMA is OK.
 *
 * @see		unuma_alloc()
 */
bool
unuma_is_broken(void)
{
	return (!unuma_enable_mbind);
}


/**
 * unuma_roundup() rounds up length to the allocation size required by pgt.
 *
 * @param [in] length	- requested length in bytes of the allocation.
 * @param [in] pgt	- page type.
 *
 * @return	required length in bytes for the allocation.
 *
 * @see		unuma_alloc(), unuma_free()
 */
size_t
unuma_roundup(size_t length, unuma_pgt_t pgt)
{
	size_t pgsz;

	if (pgt >= UNUMA_PGT_MAX)
		return (0);

	pgsz = unuma_page_size(pgt);
	return (P2ROUNDUP(length, pgsz));
}


/**
 * unuma_resv_mem() reserves an aligned range of virtual address space.
 *
 * @param [in] length	 - length in bytes of the allocation.  Must be an exact
 *                         multiple of the page type's page size.
 * @param [in] align	 - alignment of the allocation in bytes.
 *
 * @return	virtual address of the reserved memory, MAP_FAILED on failure.
 *
 * @see		unuma_do_alloc().
 */
static void *
unuma_resv_mem(size_t length, size_t align)
{
	uint8_t *mm_start, *mm_end, *vm_start, *vm_end;

	if (align <= unuma_page_size(UNUMA_PGT_SMALL))
		align = 0;

	mm_start = mmap(NULL, length + align, PROT_NONE,
	    MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);

	if (mm_start == MAP_FAILED)
		return (MAP_FAILED);

	mm_end = mm_start + length + align;
	vm_start = align ? (uint8_t *)
	    P2ROUNDUP((uintptr_t)mm_start, align) : mm_start;
	vm_end = vm_start + length;

	if (vm_start != mm_start)
		(void) munmap(mm_start, (size_t)(vm_start - mm_start));

	if (vm_end != mm_end)
		(void) munmap(vm_end, (size_t)(mm_end - vm_end));

	return (vm_start);
}


/**
 * unuma_do_alloc() allocates memory on a node(s), using the requested page
 * size.  See unuma_alloc() for the details.
 *
 * @param [in] addr	 - virtual address (MAP_FIXED semantics) or NULL.
 * @param [in] length	 - length in bytes of the allocation.  Must be an exact
 *                         multiple of the page type's page size.
 * @param [in] align	 - alignment of the allocation in bytes.  Must be an
 *                         exact multiple of the page type's page size.
 * @param [in] pgt	 - page type.
 * @param [in] node	 - NUMA node#, or -1 for all nodes.
 *
 * @return	virtual address of the allocated memory, MAP_FAILED on failure.
 *
 * @see		unuma_alloc().
 */
static void *
unuma_do_alloc(void *addr, size_t length, size_t align, unuma_pgt_t pgt,
    int node)
{
	int zero_fd = unuma_nodes.unn_zero_fd;  /* /dev/zero fd */
	int prot = PROT_READ | PROT_WRITE;
	const unuma_pgt_attr_t *pattr;
	int flags, fd, oerrno;
	unsigned long node_bm;
	uint8_t *v = MAP_FAILED;
	uint8_t *resv = NULL;
	size_t pgsz;

	if (pgt >= UNUMA_PGT_MAX) {
		errno = EINVAL;
		return (MAP_FAILED);
	}

	pattr = &unuma_pgt_attrs[pgt];
	pgsz = unuma_page_size(pgt);

	if (align < pgsz)
		align = pgsz;

	if (!IS_P2ALIGNED(addr, align) || !IS_P2ALIGNED(length, pgsz)) {
		/* length and address must be a multiple of the page size */
		errno = EINVAL;
		return (MAP_FAILED);
	}

	if (node == -1)
		node_bm = (1UL << unuma_get_nnodes()) - 1;
	else
		node_bm = (1UL << node);

	/* create a file backing if necessary */
	if ((pattr->upa_pgt_flags & UNUMA_PGTF_HUGETLBFS) != 0) {
		flags = MAP_SHARED;

		if (pattr->upa_mnt_fd == -1 || zero_fd == -1) {
			errno = EINVAL;
			return (MAP_FAILED);
		}

		if ((fd = unuma_create_file_backing(pattr->upa_mnt_fd)) == -1)
			return (MAP_FAILED);
	} else {
		flags = MAP_PRIVATE | MAP_ANONYMOUS;
		fd = -1;
	}

	if (addr == NULL && align > unuma_page_size(UNUMA_PGT_SMALL)) {
		/* reserve an aligned address range */
		if ((resv = unuma_resv_mem(length, align)) != MAP_FAILED)
			flags |= MAP_FIXED;
		else
			return (MAP_FAILED);
	}

	v = mmap(resv, length, prot, flags, fd, 0);
	oerrno = errno;

	/* close the file so the mapping, if any, is the only ref. */
	if (fd != -1)
		(void) close(fd);

	if (v == MAP_FAILED) {
		errno = oerrno;
		return (MAP_FAILED);
	}

	/*
	 * bind the pages to the requested node(s). This will fail on UMA
	 * systems, which is fine by definition.  See the unuma_enable_mbind()
	 * comments for why mbind() is conditionally called.
	 */
	if (unuma_enable_mbind) {
		(void) syscall(SYS_mbind, v, length, MPOL_BIND, &node_bm,
		    sizeof (node_bm) * 8, 0);
	}

	/*
	 * commit the pages: hugetlbfs pages are not reserved until committed.
	 * The read() is necessary since merely deref'ing the pointer from user
	 * space results in a bus error if there aren't enough pages available.
	 */
	if ((pattr->upa_pgt_flags & UNUMA_PGTF_HUGETLBFS) != 0) {
		uint64_t *lock = (node != -1 && length / pgsz > 1 ?
		    &unuma_nodes.unn_locks[node][pgt].unl_lock : NULL);

		if (lock != NULL)
			while (atomic_cas_64(lock, 0, 1) != 0)
				;

		for (uint64_t i = 0; i < length; i += pgsz)
			if (read(zero_fd, &v[i], 1) != 1) {
				(void) munmap(v, length);
				v = MAP_FAILED;
				errno = ENOMEM;
				break;
			}

		if (lock != NULL)
			*lock = 0;
	}

	if (addr != NULL && v != MAP_FAILED) {
		/*
		 * Now that the memory has safely been committed, remap it.
		 * mremap() is used instead of mmap() + MAP_FIXED above because
		 * any failure, e.g. out of large pages, would otherwise cause
		 * the user's reserved mapping passed in via addr to be
		 * munmapped in the process.
		 */
		v = mremap(v, length, length, (MREMAP_FIXED | MREMAP_MAYMOVE),
		    addr);
	}

	return (v);
}


/**
 * unuma_alloc() allocates memory on a node(s), using the requested page size
 * and alignment.  The addr and length parameter semantics are identical to
 * mmap(), with the addition of the page type and node parameters.
 *
 * The MPOL_BIND mbind() policy is used for allocations, so passing -1 for the
 * node will result in the allocations being made on the lowest node(s) with
 * available pages.  MPOL_BIND is used over MPOL_INTERLEAVE since the former
 * will strictly honor the node bitmask whereas the latter won't.
 *
 * @param [in] addr	- virtual address (MAP_FIXED semantics) or NULL.
 * @param [in] length	- length in bytes of the allocation.  Must be an exact
 *                        multiple of the page type's page size.
 * @param [in] align	- alignment of the allocation in bytes.  Must be an
 *                        exact multiple of the page type's page size, or
 *                        0 = use pgt's page size.
 * @param [in] pgt	- page type.
 * @param [in] node	- NUMA node#, or -1 for all nodes.
 *
 * @return	virtual address of the allocated memory, MAP_FAILED on failure.
 *
 * @see		unuma_set_pgt_fallback(), unuma_roundup(), unuma_free()
 */
void *
unuma_alloc(void *addr, size_t length, size_t align, unuma_pgt_t pgt, int node)
{
	void *v;

	if (align == 0)
		align = unuma_page_size(pgt);

	do {
		v = unuma_do_alloc(addr, length, align, pgt, node);
	} while (v == MAP_FAILED && unuma_pgt_fallback && pgt-- > 0);

	return (v);
}


/**
 * unuma_free() frees a range of memory allocated via unuma_alloc().
 *
 * @param [in] addr	- virtual address.
 * @param [in] length	- length in bytes of the allocation.
 *
 * @return	0 on success, -1 on failure.
 *
 * @see		unuma_alloc()
 */
int
unuma_free(void *addr, size_t length)
{
	return (munmap(addr, length));
}


/**
 * unuma_vtop() returns the physical address for the virtual address passed.
 *
 * @param [in] vaddr	- virtual address.
 * @param [out] paddr	- physical address.
 *
 * @return	0 on success, -1 on failure.
 *
 * @see		unuma_vtonode(), unuma_ptonode()
 */
int
unuma_vtop(const void *vaddr, uint64_t *paddr)
{
	int pgsz = getpagesize();                      /* pagemap pagesize */
	uintptr_t vp = (uintptr_t)vaddr / pgsz;        /* virtual page# */
	uintptr_t vo = (uintptr_t)vaddr - (vp * pgsz); /* offset into page */
	int fd = unuma_nodes.unn_pmap_fd;              /* pagemap fd */
	off64_t fo = (off64_t)vp * sizeof (uint64_t);  /* pagemap file offset */
	uint64_t en;                                   /* pagemap entry */

	if (fd == -1 || pread(fd, &en, sizeof (en), fo) != sizeof (en))
		return (-1);

	if ((en & PMAP_PRESENT) == 0)
		return (-1);

	*paddr = ((en & PMAP_FRAME) << ((en & PMAP_SMASK) >> PMAP_SOFF)) + vo;
	return (0);
}


/**
 * unuma_ptonode() returns the NUMA node# for the physical address passed.
 *
 * @param [in] paddr	- physical address.
 *
 * @return	NUMA node# on success, -1 on failure.
 *
 * @see		unuma_vtop(), unuma_vtonode()
 */
int
unuma_ptonode(uint64_t paddr)
{
	int nnodes = unuma_get_nnodes();
	unuma_info_t *ninfo;
	unuma_mrange_t *mr;

	for (int i = 0; i < nnodes; i++) {
		ninfo = &unuma_nodes.unn_info[i];

		for (int m = 0; m < ninfo->uni_npranges; m++) {
			mr = &ninfo->uni_pranges[m];

			if (paddr >= mr->umr_start &&
			    paddr < mr->umr_start + mr->umr_len)
				return (i);
		}
	}

	return (-1);
}


/**
 * unuma_vtonode() returns the NUMA node# for the virtual address passed.
 *
 * @param [in] vaddr	- virtual address.
 *
 * @return	NUMA node# on success, -1 on failure.
 *
 * @see		unuma_vtop(), unuma_ptonode()
 */
int
unuma_vtonode(const void *vaddr)
{
	uint64_t paddr;

	if (unuma_vtop(vaddr, &paddr) != 0)
		return (-1);

	return (unuma_ptonode(paddr));
}


/**
 * unuma_check_mbind() tries to discover whether mbind() works or is buggy.  See
 * unuma_is_broken() for more information.
 *
 * The check uses the following (from highest to lowest order of precedence):
 *
 *     - UNUMA_DEBUG environment variable bit 0.  1=mbind() works, 0=broken.
 *     - Known working systems (hacky): all DSSD systems have been patched.
 *     - Linux kernel version: the latest mbind() patch was applied to 3.10.5.
 *
 * Fixme: build a test that definitively catches the broken case, and
 * then throw out the existing code.  At the very least, a more restrictive
 * kernel version test could be devised (the bug goes back to at least 3.1.0-rc3
 * and was probably introduced earlier.)  We could also conceivably work around
 * the bug by providing our own custom kernel module that had a patched version
 * of mbind(), although that may be fragile from a support standpoint.
 *
 * @return	true if mbind() works, false if mbind() is buggy.
 *
 * @see		unuma_is_broken(), unuma_alloc()
 */
static bool
unuma_check_mbind(void)
{
	unsigned fmajor = 3, fminor = 10, frelease = 5;
	const char *env = getenv("UNUMA_DEBUG");
	unsigned major, minor, release;
	struct utsname uts;
	char vendor[6];
	ssize_t bread;
	int fd;

	/* UNUMA_DEBUG environment variable */
	if (env != NULL)
		return ((strtol(env, NULL, 0) & 1) != 0);

	/* Known working systems */
	if ((fd = open(unuma_vendor_file, O_RDONLY)) != -1) {
		bread = read(fd, vendor, sizeof (vendor));
		(void) close(fd);

		if (bread == 5 && memcmp(vendor, "DSSD\n", 5) == 0)
			return (true);
	}

	/* The Linux kernel version */
	if (uname(&uts) == 0 &&
	    sscanf(uts.release, "%u.%u.%u", &major, &minor, &release) == 3) {
		if (major != fmajor)
			return (major > fmajor);

		if (minor != fminor)
			return (minor > fminor);

		return (release >= frelease);
	}

	return (false);
}


/**
 * unuma_init() initializes the NUMA nodes.
 *
 * If the number of NUMA nodes is greater than UNUMA_MAX_NODES then
 * initialization fails and the number of NUMA nodes is set to -1.
 *
 * @see		unuma_fini()
 */
static void
__attribute__ ((constructor))
unuma_init(void)
{
	struct dirent *result;
	struct dirent dent;
	DIR *dirp;
	int node;

#if defined(__x86_64__)
#if defined(HAVE_LIBCPUID)
	if (cpuid_is_rdtscp_cpu_num_available())
		unuma_set_get_node(unuma_get_node_rdtscp);
#endif
#endif

	unuma_enable_mbind = unuma_check_mbind();

	/* init the global node info */
	memset(&unuma_nodes, 0, sizeof (unuma_nodes));

	for (int i = 0; i < UNUMA_MAX_NODES; i++)
		unuma_nodes.unn_info[i].uni_node = i;

	unuma_nodes.unn_zero_fd = open("/dev/zero", O_RDONLY);
	unuma_nodes.unn_pmap_fd = open("/proc/self/pagemap", O_RDONLY);
	unuma_read_uint64_file(unuma_smem_dir, "block_size_bytes", 16,
	    &unuma_nodes.unn_physmem_blksz);
	unuma_open_page_mounts();

	/* init each node */
	if ((dirp = opendir(unuma_node_dir)) == NULL) {
		/* no node directory, so assume a single node */
		unuma_init_node(0);
		return;
	}

	unuma_nodes.unn_has_node_dir = 1;
	while (readdir_r(dirp, &dent, &result) == 0 && result != NULL) {
		if (strncmp(dent.d_name, "node", 4) == 0) {
			errno = 0;
			node = strtol(dent.d_name + 4, NULL, 10);

			if (errno != 0 || node < 0)
				continue;

			if (node >= UNUMA_MAX_NODES) {
				/* too many NUMA nodes for libunuma */
				unuma_nodes.unn_nnodes = -1;
				break;
			}

			unuma_init_node(node);
		}
	}

	(void) closedir(dirp);
}


/**
 * unuma_fini() finalizes the NUMA nodes.
 *
 * @see		unuma_init()
 */
static void
__attribute__ ((destructor))
unuma_fini(void)
{
	int nnodes = unuma_get_nnodes();
	unuma_pgt_attr_t *pattr;
	unuma_info_t *n;

	/* free the physical memory range mappings */
	for (int i = 0; i < nnodes; i++) {
		n = &unuma_nodes.unn_info[i];

		if (n->uni_prange_alen > 0) {
			(void) unuma_free(n->uni_pranges, n->uni_prange_alen);
			n->uni_prange_alen = 0;
			n->uni_npranges = 0;
		}
	}

	/* close the files */
	for (unuma_pgt_t pgt = 0; pgt < UNUMA_PGT_MAX; pgt++) {
		pattr = &unuma_pgt_attrs[pgt];

		if (pattr->upa_mnt_fd != -1) {
			(void) close(pattr->upa_mnt_fd);
			pattr->upa_mnt_fd = -1;
		}
	}

	if (unuma_nodes.unn_zero_fd != -1) {
		(void) close(unuma_nodes.unn_zero_fd);
		unuma_nodes.unn_zero_fd = -1;
	}

	if (unuma_nodes.unn_pmap_fd != -1) {
		(void) close(unuma_nodes.unn_pmap_fd);
		unuma_nodes.unn_pmap_fd = -1;
	}
}
