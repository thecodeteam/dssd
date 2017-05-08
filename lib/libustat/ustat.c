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
 * Userland Statistics
 *
 * libustat provides a simple mechanism for clients to declare a namespace of
 * statistics such as integer counters and strings, and export those stats to
 * consumers.  Statistics can be examined live while the producer is running,
 * examined post-mortem from an archived file, or even read from a core file.
 * The ustat facility is inspired by the Solaris kernel kstat facility, with
 * the benefit of many lessons learned from a decade of experience with kstat.
 *
 * 1. Interface Design and Lessons Learned
 *
 * The top-level interfaces have been simplified: in particular, the notion
 * of having separate calls to create and install a stat no longer exists,
 * and the implementation notion of an update "chain" is removed as well.
 *
 * The notion of 'raw' kstats where the entire group itself is raw and has
 * no apparent structure is entirely removed.  However, individual named
 * elements that are just sequences of bytes are permitted.
 *
 * The notion of a 'class' that is a set of #defines is eliminated.  Instead,
 * class is an ops-vector that client programs can use to define their own
 * customized classes, without needing to modify this library to do so.
 *
 * The set of intrinsic types is enriched to include SIZE (formatted with
 * size suffixes), TOD, CLOCK, and DELTA (formatted as various kinds of time)
 * and UUID (an RFC 4122-style UUID) and pretty-printing routines are provided.
 *
 * The namespace hierarchy is more flexible, but names are validated against
 * an identifier syntax.  kstat enforced a rigid namespace more suited to
 * the kernel (e.g. an integer 'instance' was mandated), but did not require
 * that string names conformed to C identifier syntax, which helps debuggers.
 *
 * The value structure is now opaque, and updates to values are performed by
 * an optimized function, not by caller code.  This improvement and tradeoffs
 * associated are discussed in detail in comments for _ustat_atomic_add_int()
 * below.
 *
 * The library provides a mechanism for keeping the previous snapshot of a
 * group around and accessible, so that a client can easily compute and report
 * deltas between the latest snapshot of a group and its previous snapshot.
 *
 * 2. Namespace
 *
 * In the original kstat design, the kstat namespace consisted of the four-
 * element tuple (module, instance, gname, sname) where module and instance
 * were not restricted, and instance was an integer (i.e. a driver instance
 * number), and sname was originally optional in the case of raw kstats.
 * For the userland design, we simplify this a bit but add restrictions to
 * make things easier for accessing statistics in a debugger:
 *
 * The ustat namespace consists of the triplet (entity, group, name) where
 * entity is required to be a dot-delimited sequence of identifiers defined
 * by the caller, group is required to be an identifier, and name is required
 * to be an identifier.  As such, the "full path" to any statistic can be
 * defined by just concatenating the string to <entity>.<group>.<name>
 *
 * The ustat namespace is per-process, but ustats from multiple processes can
 * be joined by just using the /proc comm name and pid at the top of it. (The
 * ustat utility uses this form when multiple -p options are specified.)
 *
 * The 'entity' is intended to be something that identifies an abstraction in
 * the caller's program.  For example, an ftp server might use an 'entity'
 * name of "user.mws" for the stats related to my session, and therefore
 * the full path "user.mws.io.rbytes" might be how many bytes read and the
 * the full path "user.mws.auth.type" might refer to my authentication model.
 *
 * 3. Snapshot Mechanism
 *
 * The major challenge in implementing ustat is how to handle snapshots between
 * producers and consumers, whereby a consumer can get a consistent copy of a
 * stat group without imposing significant performance penalty on the producer.
 * This challenge remains unsolved.  For the time being, we favor the producer
 * and permit the consumer to read data that may be inconsistent.
 *
 * 4. Data Layout
 *
 * Our means of IPC, a shared file in /tmp, is also our data format: if you
 * simply don't delete your file, then a consumer can read your statistics
 * post-mortem with the same exact code.  And reading stats from a core file
 * is almost the same code again: instead of reading the file and mmap'ing
 * pages in order, we traverse the core's ELF Phdrs, find our pages
 * out-of-order, and map them.
 *
 * Every stat group is allocated to a single VM page.  If the entity name and
 * group name total 32 bytes, and the group consists solely of integer
 * statistics with an average name length of 8 bytes, then a ustat group can
 * accomodate 80 statistics on a system with a 4K pagesize.  The data on each
 * page is arranged as follows by ustat_insert():
 *
 * +-----------------+
 * | ustat_page_t    | <-- page magic and metadata
 * +-----------------+
 * | ustat_group_t   | <-- stat group metadata
 * +-----------------+
 * | ustat_named_t[] | <-- array of stats as specified by the caller
 * +-----------------+
 * | ustat_value_t[] | <-- array of values, one per stat
 * +-----------------+
 * | string table    | <-- array of strings (for ustat_{group,class_named}_t)
 * +-----------------+
 * | byte arrays     | <-- array of xlen bytes (for variable-length types)
 * +-----------------+
 *
 * 5. Other Userland Issues
 *
 * libustat must handle fork carefully for two reasons: (1) like any MT-safe
 * library we have to be sure we grab all our locks and then release them
 * again in both the parent and the forked child; and (2) we want our child
 * to copy all of his current statistics out to a new stat file associated
 * with the child pid, i.e. forking the file as well as the process.
 *
 * libustat must handle exec and exit because the default behavior needs to be
 * that clients do not leave an ever-increasing number of stat files around
 * the filesystem when they run.  Interposing on exit is relatively easy, but
 * exec is more complicated-- since no atexec(3) exists in UNIX, we have to
 * interpose on all the exec(2) variants, delete our file before an attempted
 * exec, and then relink our file if the exec fails.
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/param.h>

#include <assert.h>
#include <signal.h>
#include <unistd.h>
#include <alloca.h>
#include <limits.h>
#include <dirent.h>
#include <inttypes.h>
#include <ucontext.h>
#include <fnmatch.h>
#include <strings.h>
#include <string.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdarg.h>
#include <stdio.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <ctype.h>
#include <errno.h>
#include <elf.h>

#include <nelf.h>
#include <vmem.h>
#include <hrtime.h>
#include <ustat_hg.h>
#include <ustat_io.h>
#include <ustat_ms.h>
#include <ustat_impl.h>
#include <ucore.h>
#include <list.h>
#include <bson.h>

#define	UU_UUID_BIN_LEN	16
#define	UU_UUID_STR_LEN	36

#define	USTAT_ROOT_PREFIX	"/dev/shm/.ustat.%s.%d.%d."
#define	USTAT_ROOT_PATTERN	USTAT_ROOT_PREFIX "XXXXXX"

#define USTAT_ROOT_HLEN		211

#define	USTAT_ROOT_MODE		0777
#define	USTAT_STAT_MODE		0644

#define	USTAT_TYPE_BY_VAL(n)	((n)->usn_type < USTAT_TYPE_STRING)
#define	USTAT_TYPE_BY_REF(n)	((n)->usn_type >= USTAT_TYPE_STRING)

#define	USTAT_PAGE_RELO(ptr, old, new) \
    (ptr = (void *)((uintptr_t)ptr - (uintptr_t)(old) + (uintptr_t)(new)))

static int ustat_update_file(ustat_handle_t *);
static int ustat_update_core(ustat_handle_t *);
static int ustat_misc_export_bson(ustat_struct_t *, int, bson_t *, off_t);

static pthread_mutex_t ustat_lock = PTHREAD_MUTEX_INITIALIZER;
static ustat_handle_t *ustat_list = NULL;

const ustat_class_t ustat_class_misc = {
	.usc_name = "misc",
	.usc_ctor = NULL,
	.usc_dtor = NULL,
	.usc_bson = ustat_misc_export_bson,
};

static __thread int ustat_class_ctor;

static const uint8_t ustat_magicstr[] = { USTAT_MAG0, USTAT_MAG1, USTAT_MAG2 };

const ustat_unit_t ustat_unit_size = { 1024, "B\0K\0M\0G\0T\0P\0E\0" };
const ustat_unit_t ustat_unit_time = { 1000, "ns\0us\0ms\0s\0" };
const ustat_unit_t ustat_unit_iops = { 1000, "\0K\0M\0B\0T\0" };

const ustat_unit_t ustat_unit_tput =
    { 1000, "b/s\0K/s\0M/s\0G/s\0T/s\0P/s\0E/s\0" };

static const char *
ustat_strbadid(const char *s, const char *extras)
{
	const char *p;
	char c;

	if (s == NULL)
		return ((char *)-1L);

	for (p = s; (c = *p) != '\0'; p++) {
		if (isalpha(c) || c == '_')
			continue;
		else if (p > s && (isdigit(c) || strchr(extras, c) != NULL))
			continue;
		else
			return (p);
	}

	if (p == s)
		return (p);

	return (NULL);
}

static uint32_t
ustat_strhash(const char *s)
{
	uint32_t g, h = 0;
	const char *p;

	for (p = s; *p != '\0'; p++) {
		h = (h << 4) + *p;
		if ((g = (h & 0xf0000000)) != 0) {
			h ^= (g >> 24);
			h ^= g;
		}
	}

	return (h);
}

static int
ustat_env2flags(const char *v)
{
	int oflags = 0;
	char *e, *p, *q;
	size_t len;

	len = strlen(v);
	e = alloca(len + 1);
	(void) strcpy(e, v);

	for (p = strtok_r(e, ",", &q); p != NULL; p = strtok_r(NULL, ",", &q)) {
		if (strcmp(p, "abort") == 0)
			oflags |= USTAT_DEBUG_ABORT;
		else if (strcmp(p, "verbose") == 0)
			oflags |= USTAT_DEBUG_VERBOSE;
	}

	return (oflags);
}

static int __attribute__ ((format(printf, 3, 0)))
ustat_verror(const ustat_handle_t *h, int err, const char *format, va_list ap)
{
	int flags;
	char *e;

	if (h != NULL)
		flags = h->ush_oflags;
	else if ((e = getenv("USTAT_DEBUG")) != NULL)
		flags = ustat_env2flags(e);
	else
		flags = 0;

#if defined(USTAT_DEBUG)
	/*
	 * Force verbose mode when the developer has enabled USTAT_DEBUG since
	 * the whole point is to print ustat debugging messages for this state.
	 */
	flags |= USTAT_DEBUG_VERBOSE;
#endif

	if (flags & USTAT_DEBUG_VERBOSE) {
		(void) fprintf(stderr, "ustat error: ");
		(void) vfprintf(stderr, format, ap);
		(void) fprintf(stderr, "\n");
	}

	if (flags & USTAT_DEBUG_ABORT) {
		sigset_t set;

		(void) sigfillset(&set);
		(void) sigdelset(&set, SIGABRT);
		(void) sigprocmask(SIG_SETMASK, &set, NULL);
		abort();
	}

	errno = err;
	return (-1);
}

int __attribute__ ((format(printf, 3, 4)))
ustat_error(const ustat_handle_t *h, int err, const char *format, ...)
{
	va_list ap;

	va_start(ap, format);
	err = ustat_verror(h, err, format, ap);
	va_end(ap);

	return (err);
}

static inline void
ustat_caller_error(const ustat_struct_t *s, const ustat_named_t *n,
    const char *msg)
{
	const ustat_group_t *g = USTAT_STRUCT_TO_GROUP(s);

	(void) ustat_error(g->usg_handle, EINVAL, "%s.%s: %s\n",
	    g->usg_gname, n->usn_name, msg);
}

void * __attribute__ ((format(printf, 3, 4)))
ustat_null(const ustat_handle_t *h, int err, const char *format, ...)
{
	va_list ap;

	va_start(ap, format);
	(void) ustat_verror(h, err, format, ap);
	va_end(ap);

	return (NULL);
}

static bool
ustat_is_readonly(ustat_handle_t *h)
{
    return ((h->ush_oflags & O_ACCMODE) == O_RDONLY);
}

static bool
ustat_is_writeonly(ustat_handle_t *h)
{
    return ((h->ush_oflags & O_ACCMODE) == O_WRONLY);
}

static ustat_page_t *
ustat_page_mapin(ustat_handle_t *h, off_t off, size_t len, int map_type)
{
	ustat_page_t *p;
	int prot, flag;

	if (ustat_is_readonly(h) || map_type == MAP_PRIVATE) {
		prot = PROT_READ | PROT_WRITE;
		flag = MAP_PRIVATE | MAP_POPULATE;

	} else {
		prot = PROT_READ | PROT_WRITE;
		flag = MAP_SHARED;
	}

	p = mmap(NULL, len, prot, flag, h->ush_fd, off);
	return (p == MAP_FAILED ? NULL : p);
}

/*
 * We use a freelist to track unused regions of the ustat file.  When
 * inserting a new ustat, we look at the freelist before growing the file.
 * To keep interactions with asynchronous readers simple, once a region
 * of the file has been used for a page of a particular size it may only
 * be reused for new pages of the same size.
 *
 * Because most regions will be 1 page long, we maintain two lists, one
 * for 1 page regions and one for regions of all other sizes.
 */

static list_t *
ustat_freepage_list(ustat_handle_t *h, size_t size)
{
	return (size == h->ush_pgsize ? &h->ush_free_pgsz : &h->ush_free_other);
}

static void
ustat_freepage_put(ustat_handle_t *h, ustat_page_t *p)
{
	list_t *list = ustat_freepage_list(h, p->usp_size);
	ustat_freepage_t *fp;

	if ((p->usp_magic[3] & USTAT_MAG3_TYPE) != USTAT_MAG3_GRP)
		return;

	fp = vmem_zalloc(vmem_heap, sizeof (ustat_freepage_t), VM_NOFAIL);
	fp->usfp_off = p->usp_off;
	fp->usfp_size = p->usp_size;
	list_insert_head(list, fp);
}

static ustat_page_t *
ustat_freepage_get(ustat_handle_t *h, uint8_t type, size_t size)
{
	list_t *list = ustat_freepage_list(h, size);
	ustat_freepage_t *fp;
	ustat_page_t *p;
	void *s;

	if (type != USTAT_MAG3_GRP)
		return (NULL);

	for (fp = list_head(list); fp != NULL && fp->usfp_size != size;
	    fp = list_next(list, fp))
		continue;

	if (fp == NULL ||
	    (p = ustat_page_mapin(h, fp->usfp_off,
		fp->usfp_size, MAP_SHARED)) == NULL)
		return (NULL);

	/*
	 * Rezero the page, as if freshly minted.  As the ustat_page_t is
	 * the file's record marking mechanism, it must be left intact.
	 * Re-writing it manually should be a no-op, but is done anyway
	 * to ensure the correctness its primary consumer, our caller.
	 */
	s = USTAT_PAGE_TO_DATA(p);
	memset(s, 0, size - ((char *)s - (char *)p));
	p->usp_off = fp->usfp_off;

	list_delete(list, fp);
	vmem_free(vmem_heap, fp, sizeof (ustat_freepage_t));

	return (p);
}

static void
ustat_freepage_empty(list_t *l)
{
	ustat_freepage_t *fp;
	while ((fp = list_head(l)) != NULL) {
		list_delete(l, fp);
		vmem_free(vmem_heap, fp, sizeof (ustat_freepage_t));
	}
}

/*
 * Linux strangely does not support fallocate(), their own fancy system call,
 * on tmpfs.  So instead we use the older trick of writing a zero byte at the
 * end to be sure we can mmap up to a given range, and then attempt a fallocate
 * anyway, cast to void, to tell any supporting filesystem to alloc space now.
 */
static int
ustat_falloc(int fd, off_t offset, off_t len)
{
	uint8_t z = 0;

	if (pwrite(fd, &z, sizeof (z), offset + len - sizeof (z)) != sizeof (z))
		return (-1);

	(void) fallocate(fd, 0, offset, len);
	return (0);
}

static ustat_page_t *
ustat_page_create(ustat_handle_t *h, uint8_t type, size_t size)
{
	ustat_page_t *p;

	if ((p = ustat_freepage_get(h, type, size)) == NULL) {
		if (ustat_falloc(h->ush_fd, h->ush_fdlen, size) != 0)
			return (NULL);

		if ((p = ustat_page_mapin(h, h->ush_fdlen,
		    size, MAP_SHARED)) == NULL) {
			(void) ftruncate(h->ush_fd, h->ush_fdlen);
			return (NULL);
		}

		p->usp_off = h->ush_fdlen;
		h->ush_fdlen += size;
	}

	p->usp_magic[0] = USTAT_MAG0;
	p->usp_magic[1] = USTAT_MAG1;
	p->usp_magic[2] = USTAT_MAG2;
	p->usp_magic[3] = USTAT_MAG3 | type;

	p->usp_addr = p;
	p->usp_size = size;

	return (p);
}

static ustat_page_t *
ustat_page_recreate(ustat_handle_t *h, off_t off, size_t lim)
{
	ustat_page_t *p;

	if ((p = ustat_page_mapin(h, off, h->ush_pgsize, MAP_SHARED)) == NULL)
		return (NULL);

	if (bcmp(p->usp_magic, ustat_magicstr, sizeof (ustat_magicstr)) != 0) {
		(void) munmap(p, h->ush_pgsize);
		return (ustat_null(h, EINVAL, "not a ustat page: %p", p));
	}

	/*
	 * If the page's encoded size exceeds the caller's predefined limit,
	 * then treat this as if the page could not be mapped.  This might
	 * happen (for example) if a core file is truncated after the Phdrs.
	 */
	if (p->usp_size > lim) {
		(void) munmap(p, h->ush_pgsize);
		return (ustat_null(h, ERANGE,
		    "page %p size %u exceeds limit: %zu", p, p->usp_size, lim));
	}

	/*
	 * If we mapped the page with unknown size, and it appears valid,
	 * resize the mapping according to the saved size if larger than pgsize
	 */
	if (p->usp_size > h->ush_pgsize) {
		ustat_page_t *o = p;
		p = ustat_page_mapin(h, off, p->usp_size, MAP_SHARED);
		(void) munmap(o, h->ush_pgsize);
	}

	return (p);
}

static void
ustat_page_destroy(ustat_handle_t *h, ustat_page_t *p)
{
	if (p != NULL)
		(void) munmap(p, p->usp_size);
}

static ustat_page_t *
ustat_page_lookup(const void *data, size_t size)
{
	for (uintptr_t addr = (uintptr_t)data; addr != 0; addr -= size) {
		ustat_page_t *p = (ustat_page_t *)P2ALIGN(addr, size);
		if (bcmp(p->usp_magic, ustat_magicstr,
		    sizeof (ustat_magicstr)) == 0)
			return (p);
	}

	return (NULL);
}

static int
ustat_page_rewrite(ustat_handle_t *h, ustat_page_t *dst)
{
	ustat_page_t *src;

	if (pwrite(h->ush_fd, dst, dst->usp_size,
	    dst->usp_off) != (ssize_t)dst->usp_size) {
		return (ustat_error(h, errno,
		    "failed to rewrite %p (%s[%zd]): write failed: %s", (void *)
		    dst, h->ush_path, (size_t)dst->usp_off, strerror(errno)));
	}

	if ((src = ustat_page_mapin(h, dst->usp_off,
	    dst->usp_size, MAP_SHARED)) == NULL) {
		return (ustat_error(h, errno,
		    "failed to rewrite %p (%s[%zd]): mapin failed: %s", (void *)
		    dst, h->ush_path, (size_t)dst->usp_off, strerror(errno)));
	}

	if (mremap(src, src->usp_size, src->usp_size,
	    MREMAP_FIXED | MREMAP_MAYMOVE, dst) != dst) {
		ustat_page_destroy(h, src);
		return (ustat_error(h, errno,
		    "failed to rewrite %p (%s[%zd]): remap failed: %s",
		    dst, h->ush_path, (size_t)dst->usp_off, strerror(errno)));
	}

	return (0);
}

static ustat_root_t *
ustat_root_create(ustat_handle_t *h, pid_t pid,
    const char *p_comm, const char *p_args, size_t hlen)
{
	ustat_page_t *p;
	ustat_root_t *r;

	uintptr_t r_end;
	size_t len;

	if ((p = ustat_page_create(h, USTAT_MAG3_ROOT, h->ush_pgsize)) == NULL)
		return (NULL);

	r = USTAT_PAGE_TO_DATA(p);
	r_end = (uintptr_t)p + p->usp_size;

	r->usr_gen = 1;
	r->usr_pid = pid ? pid : getpid();
	r->usr_hash = (ustat_group_t **)(r + 1);
	r->usr_hlen = hlen;
	r->usr_comm = (char *)r->usr_hash + sizeof (void *) * r->usr_hlen;

	if (r->usr_comm >= (char *)r_end)
		return (ustat_null(h, EOVERFLOW, "hash len exceeds page size"));

	len = (p_comm != NULL ? strlen(p_comm) : 0) + 1;
	len = MIN(len, r_end - (uintptr_t)r->usr_comm);

	if (len != 0) {
		(void) memcpy(r->usr_comm, p_comm, len - 1);
		r->usr_comm[len - 1] = '\0';
	}

	r->usr_args = r->usr_comm + len;
	len = (p_args != NULL ? strlen(p_args) : 0) + 1;
	len = MIN(len, r_end - (uintptr_t)r->usr_args);

	if (len != 0) {
		(void) memcpy(r->usr_args, p_args, len - 1);
		r->usr_args[len - 1] = '\0';
	}

	return (r);
}

static void
ustat_root_destroy(ustat_handle_t *h, ustat_root_t *r)
{
	size_t i;

	for (i = 0; i < r->usr_hlen; i++) {
		while (r->usr_hash[i] != NULL) {
			ustat_group_t *g = r->usr_hash[i], *p;
			r->usr_hash[i] = g->usg_next;
			if ((p = g->usg_prev) != NULL)
				ustat_page_destroy(h, USTAT_DATA_TO_PAGE(h, p));
			ustat_page_destroy(h, USTAT_DATA_TO_PAGE(h, g));
		}
	}

	ustat_page_destroy(h, USTAT_DATA_TO_PAGE(h, r));
}

static ustat_root_t *
ustat_root_relocate(ustat_page_t *p)
{
	ustat_root_t *r = USTAT_PAGE_TO_DATA(p);

	USTAT_PAGE_RELO(r->usr_comm, p->usp_addr, p);
	USTAT_PAGE_RELO(r->usr_args, p->usp_addr, p);
	USTAT_PAGE_RELO(r->usr_hash, p->usp_addr, p);
	memset(r->usr_hash, 0, sizeof (ustat_group_t *) * r->usr_hlen);

	p->usp_addr = p;
	return (r);
}

static ustat_group_t *
ustat_group_relocate(ustat_handle_t *h, ustat_page_t *p)
{
	ustat_group_t *g = USTAT_PAGE_TO_DATA(p);

	ustat_named_t *n;
	ustat_value_t *v;
	uint16_t i;

	g->usg_next = NULL;
	g->usg_prev = NULL;
	g->usg_handle = h;
	g->usg_uarg = NULL;

	USTAT_PAGE_RELO(g->usg_gname, p->usp_addr, p);
	USTAT_PAGE_RELO(g->usg_cname, p->usp_addr, p);
	USTAT_PAGE_RELO(g->usg_statv, p->usp_addr, p);
	USTAT_PAGE_RELO(g->usg_datav, p->usp_addr, p);
	USTAT_PAGE_RELO(g->usg_rodata, p->usp_addr, p);
	USTAT_PAGE_RELO(g->usg_rwdata, p->usp_addr, p);

	for (n = g->usg_statv, i = 0; i < g->usg_statc; i++, n++) {
		USTAT_PAGE_RELO(n->usn_name, p->usp_addr, p);
		USTAT_PAGE_RELO(n->usn_data, p->usp_addr, p);

		if (USTAT_TYPE_BY_VAL(n))
			continue;

		v = n->usn_data;
		USTAT_PAGE_RELO(v->usv_buf, p->usp_addr, p);
	}

	p->usp_addr = p;
	return (g);
}

static int
ustat_relink(ustat_handle_t *h, char *pattern)
{
	ustat_root_t *r = h->ush_root;
	char *old_path = h->ush_path;
	int old_fd = h->ush_fd;
	int err = 0;

	char *new_path;
	int new_fd;
	ustat_group_t *g;
	uint32_t i;

	new_fd = mkostemp(pattern, h->ush_oflags & ~USTAT_OFLAGS & ~O_ACCMODE);

	if (new_fd == -1) {
		return (ustat_error(h, errno,
		    "failed to mkostemp %s: %s", pattern, strerror(errno)));
	}

	(void) unlink(pattern);

	if ((new_path = vmem_strdup(vmem_heap, pattern, VM_NOSLEEP)) == NULL) {
		(void) close(new_fd);
		return (ustat_error(h, ENOMEM, "failed to alloc buffer"));
	}

	h->ush_path = new_path;
	h->ush_fd = new_fd;

	for (i = 0; i < r->usr_hlen; i++) {
		for (g = r->usr_hash[i]; g != NULL; g = g->usg_next)
			err |= ustat_page_rewrite(h, USTAT_DATA_TO_PAGE(h, g));
	}

	if (err != 0 || ustat_page_rewrite(h, USTAT_DATA_TO_PAGE(h, r)) != 0) {
		h->ush_path = old_path;
		h->ush_fd = old_fd;

		(void) close(new_fd);
		vmem_strfree(vmem_heap, new_path);
		return (-1);
	}

	(void) close(old_fd);
	vmem_strfree(vmem_heap, old_path);
	return (0);
}

static int
ustat_reopen(ustat_handle_t *h)
{
	const bool gen = (h->ush_oflags & USTAT_PATTERN) == USTAT_PATTERN;
	struct stat st;
	int err, fd;

	fd = gen ?
	    mkostemp(h->ush_path, h->ush_oflags & ~USTAT_OFLAGS & ~O_ACCMODE) :
	    open(h->ush_path, h->ush_oflags & ~USTAT_OFLAGS, USTAT_STAT_MODE);

	if (fd != -1 && gen)
		(void) unlink(h->ush_path);

	if (fd == -1 || fstat(fd, &st) != 0) {
		err = ustat_error(h, errno,
		    "failed to open %s: %s", h->ush_path, strerror(errno));
		if (fd >= 0)
			(void) close(fd);
		return (err);
	}

	if (h->ush_fd >= 0)
		(void) close(h->ush_fd);

	h->ush_fdlen = (size_t)st.st_size;
	h->ush_fd = fd;
	return (0);
}

static void
ustat_proc_pattern(pid_t pid, uid_t uid, const char *comm, char *buf,
    size_t len)
{
	(void) snprintf(buf, len, USTAT_ROOT_PATTERN, comm, uid, pid);
}

static void
ustat_proc_prefix(pid_t pid, uid_t uid, const char *comm, char *buf, size_t len)
{
	(void) snprintf(buf, len, USTAT_ROOT_PREFIX, comm, uid, pid);
}

static void
ustat_fork(ustat_handle_t *h)
{
	ustat_root_t *r = h->ush_root;
	pid_t self = getpid();

	char path[PATH_MAX];

	if (ustat_is_readonly(h))
		return; /* no changes needed after fork */

	ustat_proc_pattern(self, getuid(), r->usr_comm, path, sizeof (path));
	(void) ustat_relink(h, path);

	r->usr_pid = self;
}

static void
ustat_fork_enter(void)
{
	ustat_handle_t *h;

	(void) pthread_mutex_lock(&ustat_lock);

	for (h = ustat_list; h != NULL; h = h->ush_link)
		(void) pthread_rwlock_wrlock(&h->ush_lock);
}

static void
ustat_fork_exit(void)
{
	ustat_handle_t *h;

	for (h = ustat_list; h != NULL; h = h->ush_link)
		(void) pthread_rwlock_unlock(&h->ush_lock);

	(void) pthread_mutex_unlock(&ustat_lock);
}

static void
ustat_fork_child(void)
{
	ustat_handle_t *h;

	for (h = ustat_list; h != NULL; h = h->ush_link)
		ustat_fork(h);

	ustat_fork_exit();
}

static void __attribute__ ((constructor))
ustat_init(void)
{
	(void) pthread_atfork(ustat_fork_enter,
	    ustat_fork_exit, ustat_fork_child);
}

static void __attribute__ ((destructor))
ustat_fini(void)
{
	while (ustat_list != NULL)
		ustat_close(ustat_list);
}

static int
ustat_proc_open(pid_t pid, const char *proc_file, int flags)
{
	char path[PATH_MAX];
	(void) snprintf(path, sizeof (path), "/proc/%d/%s", pid, proc_file);
	return (open(path, flags));
}

static int
ustat_proc_read(pid_t pid, const char *proc_file, char *buf, size_t len)
{
	ssize_t rlen;
	int fd;

	if ((fd = ustat_proc_open(pid, proc_file, O_RDONLY)) == -1)
		return (-1);

	rlen = read(fd, buf, len);
	buf[rlen > 0 ? rlen - 1 : 0] = '\0';
	(void) close(fd);

	if (rlen <= 0) {
		return (ustat_error(NULL, ESRCH,
		    "no such process: %d", (int)pid));
	}

	return (0);
}

static int
ustat_proc_uid(pid_t pid, uid_t *uid)
{
	char path[PATH_MAX];
	struct stat st;

	(void) snprintf(path, sizeof (path), "/proc/%d", pid);
	if (stat(path, &st) != 0)
		return (-1);

	*uid = st.st_uid;
	return (0);
}

static int
ustat_proc_write(pid_t pid, const char *proc_file, const char *buf, size_t len)
{
	ssize_t wlen;
	int fd;

	if ((fd = ustat_proc_open(pid, proc_file, O_WRONLY)) == -1)
		return (-1);

	wlen = write(fd, buf, len);
	(void) close(fd);

	if (wlen <= 0) {
		return (ustat_error(NULL, errno,
		    "failed to write %s: %s", proc_file, strerror(errno)));
	}

	return (0);
}

/*
 * We unlink() our ustat files immediately following their creation.  This is
 * the easiest way to avoid leaving files around after an abnormal exit, but
 * presents a challenge to other processes wishing to open them.  Fortunately,
 * readlink() on an open file descriptor's /proc/pid/fd entry will return the
 * original name of a deleted file.  Here we scan the specified process's
 * file descriptors for a link target matching the expected name, and return
 * the corresponding openable /proc/pid/fd path.
 */
static int
ustat_proc_find(pid_t pid, uid_t p_uid, const char *p_comm, char *buf,
    size_t len)
{
	char fdpath[PATH_MAX], prefix[PATH_MAX], path[PATH_MAX];
	struct dirent entry, *result;
	size_t prefix_len;
	int err, fd;
	DIR *dir;

	ustat_proc_prefix(pid, p_uid, p_comm, prefix, PATH_MAX);
	prefix_len = strlen(prefix);

	if ((fd = ustat_proc_open(pid, "fd", O_RDONLY)) == -1)
		return (-1);

	if ((dir = fdopendir(fd)) == NULL) {
		err = errno;
		(void) close(fd);
		goto error;
	}

	for (;;) {
		if ((err = readdir_r(dir, &entry, &result)) != 0)
			goto error;

		if (result == NULL) {
			err = ENOENT;
			goto error;
		}

		(void) snprintf(fdpath, PATH_MAX, "/proc/%d/%s/%s", pid, "fd",
		    entry.d_name);

		if (readlink(fdpath, path, PATH_MAX) == -1)
			continue;

		if (strncmp(prefix, path, prefix_len) == 0) {
			(void) closedir(dir);
			(void) strncpy(buf, fdpath, len);
			path[len - 1] = '\0';
			return (0);
		}
	}

error:
	if (dir != NULL)
		(void) closedir(dir);
	return (ustat_error(NULL, err, "process %d: no open ustat files found",
	    pid));
}

static int
ustat_magic(ustat_handle_t *h, const ustat_page_t *p, uint8_t type)
{
	if (bcmp(p->usp_magic, ustat_magicstr, sizeof (ustat_magicstr)) != 0) {
		return (ustat_error(h, EINVAL,
		    "ustat page is uninitialized or invalid data format"));
	}

	if ((p->usp_magic[3] & USTAT_MAG3_BASE) != USTAT_MAG3) {
		return (ustat_error(h, EINVAL,
		    "ustat data is not of the expected wordsize/endianness"));
	}

	if ((p->usp_magic[3] & USTAT_MAG3_TYPE) != type) {
		return (ustat_error(h, EINVAL,
		    "ustat data type mismatch: expected %02x, found %02x",
		    type, p->usp_magic[3] & USTAT_MAG3_TYPE));
	}

	return (0);
}

static ustat_handle_t *
ustat_open(int version, const char *path,
    pid_t pid, const char *p_comm, const char *p_args, int oflags)
{
	ustat_page_t *rp = NULL;
	ustat_handle_t *h;
	ustat_root_t *r;

	int is_file = -1, is_core = -1;
	char buf[32];
	char *e;

	if (path == NULL && pid <= 0)
		return (ustat_null(NULL, EINVAL, "no file or pid specified"));

	if ((oflags & O_ACCMODE) == O_WRONLY)
		oflags = (oflags & ~O_ACCMODE) | O_RDWR; /* for mmap() */

	if ((h = vmem_zalloc(vmem_heap, sizeof (ustat_handle_t),
	    VM_NOSLEEP)) == NULL)
		return (ustat_null(NULL, ENOMEM, "failed to alloc handle"));

	(void) pthread_rwlock_init(&h->ush_lock, NULL);
	h->ush_version = version;
	h->ush_oflags = oflags | O_CLOEXEC;
	h->ush_pgsize = sysconf(_SC_PAGESIZE);
	if (pid != -1)
		h->ush_self = pid == getpid() &&
		    (oflags & O_ACCMODE) != O_RDONLY;
	else if ((oflags & O_CREAT) == O_CREAT)
		h->ush_self = 1;  /* ustat file created by this pid */
	h->ush_fd = -1;

	list_init(&h->ush_free_pgsz, offsetof(ustat_freepage_t, usfp_node));
	list_init(&h->ush_free_other, offsetof(ustat_freepage_t, usfp_node));

	if (h->ush_self && (oflags & O_CREAT))
		h->ush_oflags |= O_TRUNC;

	if ((e = getenv("USTAT_DEBUG")) != NULL)
		h->ush_oflags |= ustat_env2flags(e);

	if (path == NULL)
		goto no_path;

	if ((h->ush_path = vmem_strdup(vmem_heap, path, VM_NOSLEEP)) == NULL) {
		ustat_close(h);
		return (ustat_null(NULL, ENOMEM, "failed to alloc path"));
	}

	if (ustat_reopen(h) != 0) {
		ustat_close(h);
		return (NULL);
	}
no_path:

	/*
	 * If the file has at least a page worth of data, map in the first
	 * page and sniff it for either our magic bytes or the ELF magic bytes.
	 * If we don't find either or the page is truncated, set rp = NULL.
	 */
	if (h->ush_fdlen >= h->ush_pgsize &&
	    (rp = ustat_page_mapin(h, 0, h->ush_pgsize, MAP_SHARED)) != NULL &&
	    (is_file = ustat_magic(h, rp, USTAT_MAG3_ROOT)) != 0) {
		is_core = bcmp(rp, ELFMAG, SELFMAG);
		(void) munmap(USTAT_DATA_TO_PAGE(h, rp), h->ush_pgsize);
		rp = NULL;
	} else if (h->ush_fdlen < h->ush_pgsize) {
		(void) ustat_error(h, EINVAL,
		    "ustat file is empty or truncated");
		rp = NULL;
	}

	if (rp == NULL && (h->ush_oflags & O_CREAT))
		r = ustat_root_create(h, pid, p_comm, p_args, USTAT_ROOT_HLEN);
	else if (rp != NULL)
		r = ustat_root_relocate(rp);
	else
		r = NULL;

	if ((h->ush_root = r) == NULL && is_core != 0) {
		ustat_close(h);
		return (NULL);
	}

	/*
	 * To ensure ustats are retained in core dumps, turn on the
	 * MMF_DUMP_MAPPED_SHARED bit in the core dump filter.  Unfortunately
	 * the interface geniuses have (a) provided no interface to this,
	 * and (b) put the MMF_DUMP_* flags under __KERNEL__ in linux/sched.h
	 * despite other flags not being there, so we can't even compile
	 * against it.  Thankfully, core(5) tells us "bit 3" is what we want.
	 * That sure makes me feel better about this code being highly stable.
	 */
	if (h->ush_self && pid != -1 && ustat_proc_read(pid,
	    "coredump_filter", buf, sizeof (buf)) == 0) {
		unsigned long f = strtoul(buf, NULL, 16);
		size_t n = snprintf(buf, sizeof (buf), "0x%lx\n", f | (1 << 3));
		(void) ustat_proc_write(pid, "coredump_filter", buf, n);
	}

	if (is_core == 0)
		h->ush_update = ustat_update_core;
	else
		h->ush_update = ustat_update_file;

	(void) pthread_mutex_lock(&ustat_lock);
	h->ush_link = ustat_list;
	ustat_list = h;
	(void) pthread_mutex_unlock(&ustat_lock);

	return (h);
}

ustat_handle_t *
ustat_open_proc(int version, pid_t pid, int oflags)
{
	pid_t self = getpid();
	ustat_handle_t *h = NULL;

	char p_comm[PATH_MAX];
	char p_misc[PATH_MAX];
	char p_path[PATH_MAX];
	uid_t p_uid;
	char *p1, *p2;
	size_t len;

	if (version != USTAT_VERSION) {
		return (ustat_null(NULL, EINVAL, "invalid version: "
		    "expected %d, got %d", USTAT_VERSION, version));
	}

	if (pid == 0)
		pid = self;

	if (pid != self && (oflags & O_ACCMODE) != O_RDONLY) {
		return (ustat_null(NULL, EPERM,
		    "cannot open stats for writing: %d", pid));
	}

	if ((oflags & O_ACCMODE) == O_RDONLY && (oflags & O_CREAT) == O_CREAT ||
	    (oflags & O_ACCMODE) != O_RDONLY && (oflags & O_CREAT) != O_CREAT)
		return (ustat_null(NULL, EINVAL, "invalid open flags"));

	if (ustat_proc_read(pid, "comm", p_comm, sizeof (p_comm)) != 0) {
		/*
		 * /proc/PID/comm was introduced in a post-2.6.32+ Linux
		 * kernel, so on EL6 we fall back to parsing /proc/PID/stat
		 * to retrieve comm like ps(1) does.
		 */
		if (ustat_proc_read(pid, "stat", p_comm, sizeof (p_comm)) != 0)
			return (ustat_null(NULL, errno,
			    "errno %d @ stat: pid %d", errno, pid));
		/*
		 * /proc/stat format (using ps(1) format specifiers) is:
		 * 	pid (comm) s NNN
		 * with NNN being repeated space-separated numeric strings.
		 * comm is typically limited to 15 characters.
		 */
		p1 = strchr(p_comm, '(');
		p2 = strrchr(p_comm, ')');

		if (p1 == NULL || p2 <= p1)
			return (ustat_null(NULL, EPROTO,
			    "unexpected data format in /proc/%d/stat", pid));

		len = p2 - p1;
		p1 += 1;
		*p2 = '\0';

		(void) memmove(p_comm, p1, len);
	}

	if (ustat_proc_uid(pid, &p_uid) != 0)
		return (ustat_null(NULL, errno, "errno %d @ uid", errno));

	if ((oflags & O_ACCMODE) == O_RDONLY) {
		oflags &= ~USTAT_PATTERN;

		if (ustat_proc_find(pid, p_uid, p_comm, p_path,
		    sizeof (p_path)) == 0)
			h = ustat_open_file(version, p_path, oflags);

		if (h == NULL && errno == ENOENT) {
			(void) ustat_null(NULL, ENOENT,
			    "process %d has not published any ustats", pid);
		}

		return (h);
	}

	ustat_proc_pattern(pid, p_uid, p_comm, p_path, sizeof (p_path));
	oflags |= USTAT_PATTERN;

	/* We are opening ourself for writing. */
	assert(pid == self);

	if (ustat_proc_read(pid, "cmdline", p_misc, sizeof (p_misc)) != 0)
		return (ustat_null(NULL, errno, "errno %d @ cmdline", errno));

	return (ustat_open(version, p_path, pid, p_comm, p_misc, oflags));
}

ustat_handle_t *
ustat_open_file(int version, const char *file, int oflags)
{
	ustat_handle_t *h;

	if (version != USTAT_VERSION) {
		return (ustat_null(NULL, EINVAL, "invalid version: "
		    "expected %d, got %d", USTAT_VERSION, version));
	}

	/*
	 * At present we do not support opening a ustat file other than
	 * O_RDONLY and then modifying it.  This can be supported with a modest
	 * amount of code but unclear if any use case actually requires it.
	 */
	if ((oflags & O_ACCMODE) != O_RDONLY || (oflags & O_CREAT)) {
		return (ustat_null(NULL, EPERM,
		    "can't open ustat file for writing: use ustat_open_proc"));
	}

	if ((h = ustat_open(version, file, -1, NULL, NULL, oflags)) == NULL)
		return (NULL);

	/*
	 * Reset ush_fdlen and r->usr_gen in order to force ustat_update()
	 * to discover the entire current hash table of groups.
	 */
	h->ush_fdlen = h->ush_pgsize;
	if (h->ush_root != NULL)
		h->ush_root->usr_gen = 0;

	if (ustat_update(h) == 0)
		return (h);

	ustat_close(h);
	return (NULL);
}

/*
 * Open a memory-backed ustat instance.  'name' is expected to be a unique
 * string name for the instance.
 *
 * The implementation currently uses a file to back the memory, however this
 * may change in the future.
 */
ustat_handle_t *
ustat_open_mem(int version, const char *name)
{
	int oflags = O_CREAT | O_RDWR | USTAT_PATTERN;
	char path[PATH_MAX];
	ustat_handle_t *h;

	if (version != USTAT_VERSION) {
		return (ustat_null(NULL, EINVAL, "invalid version: "
		    "expected %d, got %d", USTAT_VERSION, version));
	}

	ustat_proc_pattern(getpid(), getuid(), name, path, sizeof (path));
	h = ustat_open(version, path, -1, NULL, NULL, oflags);

	if (h == NULL)
		return (NULL);

	h->ush_fdlen = h->ush_pgsize; /* header is present now */
	h->ush_ismem = true;
	return (h);
}

void
ustat_close(ustat_handle_t *h)
{
	ustat_handle_t **p, *q;

	(void) pthread_mutex_lock(&ustat_lock);

	for (p = &ustat_list; (q = *p) != NULL; p = &q->ush_link) {
		if (q == h) {
			*p = h->ush_link;
			break;
		}
	}

	(void) pthread_mutex_unlock(&ustat_lock);

	if (h->ush_root != NULL && !(h->ush_oflags & USTAT_RETAIN_MAPPINGS))
		ustat_root_destroy(h, h->ush_root);

	if (h->ush_fd >= 0)
		(void) close(h->ush_fd);

	ustat_freepage_empty(&h->ush_free_pgsz);
	ustat_freepage_empty(&h->ush_free_other);
	list_fini(&h->ush_free_pgsz);
	list_fini(&h->ush_free_other);

	vmem_strfree(vmem_heap, h->ush_path);
	vmem_free(vmem_heap, h, sizeof (ustat_handle_t));
}

ssize_t
ustat_conf(ustat_handle_t *h, ustat_conf_t c)
{
	ssize_t rv;

	switch (c) {
	case USTAT_CONF_PATH_MAX:
	case USTAT_CONF_NAME_MAX:
	case USTAT_CONF_XLEN_MAX:
		rv = h->ush_pgsize - sizeof (ustat_group_t) -
		    sizeof (ustat_named_t) - sizeof (ustat_value_t);
		break;
	default:
		rv = ustat_error(h, EINVAL, "invalid conf: %u", c);
		break;
	}

	return (rv);
}

pid_t
ustat_pid(ustat_handle_t *h)
{
	return (h->ush_root->usr_pid);
}

const char *
ustat_comm(ustat_handle_t *h)
{
	return (h->ush_root->usr_comm);
}

const char *
ustat_args(ustat_handle_t *h)
{
	return (h->ush_root->usr_args);
}

int
ustat_walk(ustat_handle_t *h, const char *name, ustat_walk_f *func, void *uarg)
{
	ustat_root_t *r = h->ush_root;
	int err = 0;

	ustat_group_t *g;
	ustat_struct_t *s;
	uint32_t i;

	if (ustat_is_writeonly(h))
		return (ustat_error(h, EPERM, "ustat handle is write-only"));

	(void) pthread_rwlock_rdlock(&h->ush_lock);

	for (i = 0; i < r->usr_hlen; i++) {
		for (g = r->usr_hash[i]; g != NULL; g = g->usg_next) {
			if (name != NULL && fnmatch(name, g->usg_gname, 0) != 0)
				continue;

			if (!(g->usg_flags & USTAT_F_INSERTED))
				continue;

			s = USTAT_GROUP_TO_STRUCT(g);
			err = func(h, s, uarg);

			if (err != 0)
				goto out;
		}
	}
out:
	(void) pthread_rwlock_unlock(&h->ush_lock);
	return (err);
}

static ustat_group_t *
ustat_lookup_locked(ustat_handle_t *h, const char *ename, const char *gname)
{
	ustat_root_t *r = h->ush_root;
	ustat_group_t *g;

	char *buf;
	size_t len;
	uint32_t i;

	len = strlen(ename) + 1 + strlen(gname) + 1;
	buf = alloca(len);
	(void) snprintf(buf, len, "%s.%s", ename, gname);
	i = ustat_strhash(buf) % r->usr_hlen;

	for (g = r->usr_hash[i]; g != NULL; g = g->usg_next) {
		if (!(g->usg_flags & USTAT_F_INSERTED))
			continue;
		if (strcmp(g->usg_gname, buf) == 0)
			break;
	}

	return (g);
}

ustat_named_t *
ustat_lookup(ustat_handle_t *h,
    const char *ename, const char *gname, const char *nname)
{
	ustat_group_t *g;
	ustat_named_t *n;
	uint32_t i;

	if (ename == NULL || gname == NULL)
		return (ustat_null(h, EINVAL, "invalid ename or gname"));

	if (ustat_is_writeonly(h))
		return (ustat_null(h, EPERM, "ustat handle is write-only"));

	(void) pthread_rwlock_rdlock(&h->ush_lock);

	g = ustat_lookup_locked(h, ename, gname);
	n = g ? g->usg_statv : NULL;

	if (g == NULL || nname == NULL)
		goto out;

	for (i = 0; i < g->usg_statc; i++, n++) {
		if (strcmp(n->usn_name, nname) == 0)
			break;
	}

	if (i >= g->usg_statc)
		n = NULL;
out:
	(void) pthread_rwlock_unlock(&h->ush_lock);
	return (n);
}

ustat_struct_t *ustat_lookup_struct(ustat_handle_t *h,
    const char *ename, const char *gname)
{
    return (ustat_lookup(h, ename, gname, NULL));
}


static void
ustat_insert_locked(ustat_handle_t *h, ustat_group_t *g)
{
	ustat_root_t *r = h->ush_root;
	uint32_t ghash = ustat_strhash(g->usg_gname) % r->usr_hlen;

	g->usg_next = r->usr_hash[ghash];
	r->usr_hash[ghash] = g;
}

ustat_struct_t *
ustat_insert(ustat_handle_t *h,
    const char *ename, const char *gname, const ustat_class_t *cp,
    int statc, const ustat_struct_t *statv, void *uarg)
{
	const ustat_named_t *srcv = statv;
	ustat_named_t *dstv;

	ustat_group_t *g;
	ustat_page_t *p;

	size_t group_off, statv_off, datav_off, rodat_off, rwdat_off;
	size_t statv_len, datav_len, rodat_len, rwdat_len, name_len;

	size_t upage_len;
	ustat_value_t *v;
	uint8_t *x;
	char *s;

	int i, pad, import = 0;
	uintptr_t base;

	if (ustat_strbadid(ename, ".")) {
		return (ustat_null(h, EINVAL,
		    "invalid ustat entity name: %s", ename));
	}

	if (ustat_strbadid(gname, "")) {
		return (ustat_null(h, EINVAL,
		    "invalid ustat group name: %s", gname));
	}

	if (statc > UINT16_MAX) {
		return (ustat_null(h, EOVERFLOW,
		    "too many statistics for group: %d > UINT16_MAX", statc));
	}

	if (ustat_is_readonly(h))
		return (ustat_null(h, EPERM, "ustat handle is read-only"));

	/*
	 * If this group has a constructor, then call it, which will then call
	 * back to ustat_insert() recursively.  If we succeed, reset usg_uarg
	 * to be the top-level arg.
	 */
	if (cp->usc_ctor != NULL && ustat_class_ctor == 0) {
		ustat_struct_t *rv;

		ustat_class_ctor++;
		rv = cp->usc_ctor(h, ename, gname, statc, statv, uarg);
		ustat_class_ctor--;

		if (rv != NULL)
			USTAT_STRUCT_TO_GROUP(rv)->usg_uarg = uarg;

		return (rv);
	}

	group_off = (size_t)USTAT_PAGE_TO_DATA(NULL);
	statv_off = (size_t)USTAT_GROUP_TO_STRUCT(group_off);
	statv_len = sizeof (ustat_named_t) * statc;

	/* ustat_value_t is required to be 64-bit aligned for correctness */
	datav_off = P2ROUNDUP(statv_off + statv_len, sizeof (uint64_t));
	datav_len = sizeof (ustat_value_t) * statc;

	rodat_off = datav_off + datav_len;
	rodat_len = strlen(ename) + 1 + strlen(gname) + 1 +
	    strlen(cp->usc_name) + 1;

	rwdat_off = 0;
	rwdat_len = 0;

	for (i = 0; i < statc; i++) {
		if (ustat_strbadid(srcv[i].usn_name, "")) {
			return (ustat_null(h, EINVAL,
			    "invalid ustat name: %s", srcv[i].usn_name));
		}
		rodat_len += strlen(srcv[i].usn_name) + 1;
		rwdat_len += srcv[i].usn_xlen;
	}

	rwdat_off = rodat_off + rodat_len;
	upage_len = P2ROUNDUP(rwdat_off + rwdat_len, h->ush_pgsize);

	(void) pthread_rwlock_wrlock(&h->ush_lock);

	if (ustat_lookup_locked(h, ename, gname) != NULL) {
		(void) pthread_rwlock_unlock(&h->ush_lock);
		return (ustat_null(h, EEXIST,
		    "ustat group %s.%s already exists", ename, gname));
	}

	if ((p = ustat_page_create(h, USTAT_MAG3_GRP, upage_len)) == NULL) {
		(void) pthread_rwlock_unlock(&h->ush_lock);
		return (ustat_null(h, errno,
		    "failed to create ustat page for %s.%s", ename, gname));
	}

	base = (uintptr_t)p->usp_addr;
	g = USTAT_PAGE_TO_DATA(p);

	g->usg_handle = h;
	g->usg_carg = g->usg_uarg = uarg;
	g->usg_ctime = gethrtime();
	g->usg_atime = g->usg_ctime;
	g->usg_statc = (uint16_t)statc;
	g->usg_statv = dstv = (ustat_named_t *)(base + statv_off);
	g->usg_datav = v = (ustat_value_t *)(base + datav_off);
	g->usg_rodata = s = (char *)(base + rodat_off);
	g->usg_rwdata = x = (uint8_t *)(base + rwdat_off);

	g->usg_gname = s;
	s += sprintf(s, "%s.%s", ename, gname) + 1;

	g->usg_cname = s;
	s += sprintf(s, "%s", cp->usc_name) + 1;

	for (i = 0; i < statc; i++) {
		const ustat_named_t *src = srcv + i;
		ustat_named_t *dst = dstv + i;

		if (src->usn_data != NULL)
			import++;

		dst->usn_name = s;
		name_len = strlen(src->usn_name) + 1;
		bcopy(src->usn_name, s, name_len);
		dst->usn_type = src->usn_type;
		dst->usn_xlen = src->usn_xlen;
		dst->usn_data = v;

		if (USTAT_TYPE_BY_REF(src))
			switch (src->usn_type) {
			case USTAT_TYPE_ARRAY_U64:
				pad = P2NPHASE((uintptr_t)x, sizeof (uint64_t));
				s += pad;
				x += pad;
				v->usv_buf_u64 = (uint64_t *)x;
				break;
			default:
				v->usv_buf = x;
			}
		v++;
		s += name_len;
		x += src->usn_xlen;
	}

	g->usg_flags |= USTAT_F_INSERTED;
	ustat_insert_locked(h, g);
	h->ush_root->usr_gen++;

	(void) pthread_rwlock_unlock(&h->ush_lock);

	if (import > 0)
		ustat_importv(USTAT_GROUP_TO_STRUCT(g), statc, statv);

	return (USTAT_GROUP_TO_STRUCT(g));
}

static int
ustat_delete_locked(ustat_handle_t *h, ustat_group_t *g)
{
	ustat_root_t *r = h->ush_root;
	const ustat_class_t *uc;
	ustat_group_t *q, **qp;
	uint32_t ghash;

	ghash = ustat_strhash(g->usg_gname) % r->usr_hlen;

	for (qp = &r->usr_hash[ghash]; (q = *qp) != NULL; qp = &q->usg_next) {
		if (q == g)
			break;
	}

	if (q == NULL) {
		return (ustat_error(h, ESRCH,
		    "stat not found: %p", USTAT_GROUP_TO_STRUCT(g)));
	}

	if (h->ush_self) {
		uc = ustat_cname_to_class(g->usg_cname);

		if (uc->usc_dtor != NULL && uc->usc_dtor(h, g->usg_carg) != 0)
			return (-1);
	}

	*qp = g->usg_next;
	return (0);
}

int
ustat_delete(ustat_struct_t *s)
{
	ustat_group_t *g;
	ustat_handle_t *h;
	ustat_page_t *p;
	int err;

	if (s == NULL)
		return (0); /* simplify caller code */

	g = USTAT_STRUCT_TO_GROUP(s);
	h = g->usg_handle;
	p = USTAT_DATA_TO_PAGE(h, g);

	if (ustat_is_readonly(h))
		return (ustat_error(h, EPERM, "ustat handle is read-only"));

	(void) pthread_rwlock_wrlock(&h->ush_lock);

	if ((err = ustat_delete_locked(h, g)) == 0) {
		__sync_fetch_and_and(&g->usg_flags, ~USTAT_F_INSERTED);
		h->ush_root->usr_gen++;
		ustat_freepage_put(h, p);
	}

	(void) pthread_rwlock_unlock(&h->ush_lock);

	if (err == 0)
		ustat_page_destroy(h, p);

	return (err);
}

static int
ustat_update_page(ustat_handle_t *h, ustat_page_t *p)
{
	ustat_root_t *r = h->ush_root;
	ustat_group_t *g;
	uint32_t ghash;

	if (ustat_magic(h, p, USTAT_MAG3_GRP) != 0) {
		ustat_page_destroy(h, p);
		return (-1);
	}

	g = USTAT_PAGE_TO_DATA(p);
	g->usg_atime = gethrtime();
	g = ustat_group_relocate(h, p);
	g->usg_handle = h;

	if (!(g->usg_flags & USTAT_F_INSERTED)) {
		ustat_page_destroy(h, p);
		return (0);
	}

	ghash = ustat_strhash(g->usg_gname) % r->usr_hlen;
	g->usg_next = r->usr_hash[ghash];
	r->usr_hash[ghash] = g;

	return (0);
}

static int
ustat_update_file(ustat_handle_t *h)
{
	ustat_page_t *p = ustat_page_mapin(h, 0, h->ush_pgsize, MAP_SHARED);
	ustat_root_t *r = USTAT_PAGE_TO_DATA(p);

	size_t off;

	if (p == NULL) {
		return (ustat_error(h, errno,
		    "failed to update root page: %s", strerror(errno)));
	}

	if (r->usr_gen <= h->ush_root->usr_gen) {
		ustat_page_destroy(h, p);
		return (0); /* no inserts or deletes since last update */
	}

	ustat_root_destroy(h, h->ush_root);
	h->ush_root = r = ustat_root_relocate(p);

	for (off = h->ush_pgsize; off < h->ush_fdlen; ) {
		if ((p = ustat_page_recreate(h, off,
		    h->ush_fdlen - off)) == NULL) {
			(void) ustat_error(h, errno, "failed to update group "
			    "at %zu: %s", (size_t)off, strerror(errno));
			off += h->ush_pgsize;
		} else {
			off += p->usp_size;
			(void) ustat_update_page(h, p);
		}
	}

	return (0);
}

static ustat_page_t *
ustat_mapin_phdr(ustat_handle_t *h, const void *p)
{
	const NElf_Phdr *pp = p;

	if (pp->p_type != PT_LOAD || pp->p_filesz == 0)
		return (NULL);

	if ((pp->p_flags & (PF_R | PF_W | PF_X)) != (PF_R | PF_W))
		return (NULL);

	return (ustat_page_recreate(h, (off_t)pp->p_offset, pp->p_filesz));
}

static int
ustat_update_core_class(ustat_handle_t *h,
    off_t e_phoff, size_t e_phentsize, size_t e_phnum,
    ustat_page_t *(*mapin_phdr)(ustat_handle_t *, const void *))
{
	ustat_page_t *gp, *rp = NULL;
	ustat_root_t *r;
	uint8_t *p, *q;
	int err = 0;

	size_t len = e_phentsize * e_phnum;
	uint8_t *buf = vmem_alloc(vmem_heap, len, VM_NOSLEEP);

	if (buf == NULL)
		return (ustat_error(h, ENOMEM, "failed to alloc phdrs buffer"));

	if (pread(h->ush_fd, buf, len, e_phoff) != (ssize_t)len) {
		err = ustat_error(h, errno, "failed to read phdrs");
		goto out;
	}

	for (p = buf, q = buf + len; p < q; p += e_phentsize) {
		if ((rp = mapin_phdr(h, p)) == NULL)
			continue;

		if (ustat_magic(h, rp, USTAT_MAG3_ROOT) == 0)
			break;

		ustat_page_destroy(h, USTAT_DATA_TO_PAGE(h, rp));
		rp = NULL;
	}

	if (rp == NULL) {
		err = ustat_error(h, ESRCH, "no ustats found in core file");
		goto out;
	}

	assert(h->ush_root == NULL);
	h->ush_root = r = ustat_root_relocate(rp);

	for (p = buf, q = buf + len; p < q; p += e_phentsize) {
		if ((gp = mapin_phdr(h, p)) != NULL)
			(void) ustat_update_page(h, gp);
	}
out:
	vmem_free(vmem_heap, buf, len);
	return (err);
}

static int
ustat_update_core(ustat_handle_t *h)
{
	const NElf_Ehdr *e;
	void *ehdr;
	int err;

	if (h->ush_root != NULL && h->ush_root->usr_gen != 0)
		return (0);

	if ((ehdr = mmap(NULL, h->ush_pgsize,
	    PROT_READ, MAP_PRIVATE, h->ush_fd, 0)) == MAP_FAILED) {
		return (ustat_error(h, errno,
		    "failed to mapin core header: %s", strerror(errno)));
	}

	e = ehdr;

	if (e->e_ident[EI_CLASS] != NELFCLASS) {
		(void) munmap(ehdr, h->ush_pgsize);
		return (ustat_error(h, EINVAL,
#if __WORDSIZE == 64
		    "32-bit ustat required to examine 32-bit core file"));
#elif __WORDSIZE == 32
		    "64-bit ustat required to examine 64-bit core file"));
#endif
	}

	if (e->e_ident[EI_DATA] != NELFDATA)
		err = ustat_error(h, EINVAL, "file endian-ness mismatch");
	else if (e->e_type != ET_CORE)
		err = ustat_error(h, EINVAL, "file is not an ELF core file");
	else
		err = ustat_update_core_class(h, e->e_phoff,
		    e->e_phentsize, e->e_phnum, ustat_mapin_phdr);

	(void) munmap(ehdr, h->ush_pgsize);
	return (err);
}

int
ustat_update(ustat_handle_t *h)
{
	struct stat st;

	if (!ustat_is_readonly(h))
		return (0); /* nothing to do if this is the live copy */

	if (fstat(h->ush_fd, &st) != 0) {
		return (ustat_error(h, errno, "failed to stat %s: %s",
		    h->ush_path, strerror(errno)));
	}

	if (h->ush_fdlen > (size_t)st.st_size) {
		return (ustat_error(h, ERANGE, "ustat data file truncated: "
		    "old=%zu, new=%zu", h->ush_fdlen, (size_t)st.st_size));
	}

	h->ush_fdlen = (size_t)st.st_size;
	return (h->ush_update(h));
}

ustat_struct_t *
ustat_snapshot(ustat_struct_t *s)
{
	ustat_handle_t *h;

	ustat_page_t *src, *dst;
	ustat_group_t *old, *old_next, *new;

	old = USTAT_STRUCT_TO_GROUP(s);
	old_next = old->usg_next;
	h = old->usg_handle;

	if (!(ustat_is_readonly(h) || h->ush_ismem))
		return (s);

	if (h->ush_update == ustat_update_core)
		return (s);

	dst = USTAT_DATA_TO_PAGE(h, old);
	if ((src = ustat_page_mapin(h, dst->usp_off,
	    dst->usp_size, MAP_PRIVATE)) == NULL) {
		return (ustat_null(h, errno,
		    "failed to snap page for %s (offset %zu): %s",
		    old->usg_gname, (size_t)dst->usp_off, strerror(errno)));
	}

	new = USTAT_PAGE_TO_DATA(src);
	new->usg_atime = gethrtime();

	/*
	 * If the page has been deleted or reused, return the old version.
	 * A new occupant won't be seen until the next ustat_update().
	 */
	if (!(new->usg_flags & USTAT_F_INSERTED) ||
	    new->usg_ctime != old->usg_ctime) {
		ustat_page_destroy(h, src);
		return (s);
	}

	/*
	 * Up to this point, we've just been creating mappings that no one
	 * else can see so we don't need any locks.  Once we get this far,
	 * we need to hold the hash lock as reader to be sure that no one
	 * can delete the new group we're hashing in while we're busy here.
	 */
	(void) pthread_rwlock_rdlock(&h->ush_lock);

	if (h->ush_oflags & USTAT_RETAIN_DELTA) {
		(void) ustat_delete_locked(h, old);
		new = ustat_group_relocate(h, src);
		ustat_insert_locked(h, new);

		ustat_page_destroy(h, USTAT_DATA_TO_PAGE(h, old->usg_prev));
		old->usg_prev = NULL;
		new->usg_prev = old;

	} else if (mremap(src, src->usp_size, src->usp_size,
	    MREMAP_FIXED | MREMAP_MAYMOVE, dst) == dst) {
		new = ustat_group_relocate(h, dst);
		new->usg_next = old_next;

	} else {
		new = ustat_null(h, errno,
		    "failed to snap page for %s (remap %p to dst=%p): %s",
		    old->usg_gname, (void *)src, (void *)dst, strerror(errno));
		ustat_page_destroy(h, src);
	}

	(void) pthread_rwlock_unlock(&h->ush_lock);
	return (new ? USTAT_GROUP_TO_STRUCT(new) : NULL);
}

ustat_struct_t *
ustat_previous(ustat_struct_t *s)
{
	ustat_group_t *g = USTAT_STRUCT_TO_GROUP(s)->usg_prev;
	return (g ? USTAT_GROUP_TO_STRUCT(g) : NULL);
}

const ustat_class_t *
ustat_cname_to_class(const char *cname)
{
	if (strcmp(cname, "hg") == 0)
		return (&ustat_class_hg);
	else if (strcmp(cname, "io") == 0)
		return (&ustat_class_io);
	else if (strcmp(cname, "ms") == 0)
		return (&ustat_class_ms);

	return (&ustat_class_misc);
}

void
ustat_import(ustat_struct_t *s, ustat_named_t *dst, void *src)
{
	switch (dst->usn_type) {
	case USTAT_TYPE_INT8:
		ustat_atomic_set_i8(s, dst, *(int8_t *)src);
		break;
	case USTAT_TYPE_INT16:
		ustat_atomic_set_i16(s, dst, *(int16_t *)src);
		break;
	case USTAT_TYPE_INT32:
		ustat_atomic_set_i32(s, dst, *(int32_t *)src);
		break;
	case USTAT_TYPE_INT64:
		ustat_atomic_set_i64(s, dst, *(int64_t *)src);
		break;
	case USTAT_TYPE_UINT8:
		ustat_atomic_set_u8(s, dst, *(uint8_t *)src);
		break;
	case USTAT_TYPE_UINT16:
		ustat_atomic_set_u16(s, dst, *(uint16_t *)src);
		break;
	case USTAT_TYPE_UINT32:
		ustat_atomic_set_u32(s, dst, *(uint32_t *)src);
		break;
	case USTAT_TYPE_SIZE:
	case USTAT_TYPE_UINT64:
	case USTAT_TYPE_DELTA:
		ustat_atomic_set_u64(s, dst, *(uint64_t *)src);
		break;
	case USTAT_TYPE_CLOCK:
		ustat_atomic_set_clock(s, dst, src);
		break;
	case USTAT_TYPE_TOD:
		ustat_atomic_set_tod(s, dst, src);
		break;
	case USTAT_TYPE_STRING:
		ustat_set_string(s, dst, *(const char **)src);
		break;
	case USTAT_TYPE_BYTES:
		ustat_set_bytes(s, dst, *(const uint8_t **)src, dst->usn_xlen);
		break;
	case USTAT_TYPE_ARRAY_U64:
		ustat_set_array_u64(s, dst, *(const uint64_t **)src,
		    dst->usn_xlen / sizeof (uint64_t));
		break;
	case USTAT_TYPE_UUID:
		ustat_set_uuid(s, dst, src);
		break;
	case USTAT_TYPE_MAX:
		break;
	}
}

void
ustat_importv(ustat_struct_t *s, int statc, const ustat_struct_t *statv)
{
	ustat_group_t *g = USTAT_STRUCT_TO_GROUP(s);
	uint16_t i, n = MIN(statc, g->usg_statc);
	const ustat_named_t *src = statv;
	ustat_named_t *dst = g->usg_statv;

	for (i = 0; i < n; i++, src++, dst++) {
		if (src->usn_type == dst->usn_type && src->usn_data != NULL)
			ustat_import(g->usg_statv, dst, src->usn_data);
	}
}

void
ustat_export(ustat_struct_t *s, const ustat_named_t *src, void *dst)
{
	switch (src->usn_type) {
	case USTAT_TYPE_INT8:
		*(int8_t *)dst = ustat_get_i8(s, src);
		break;
	case USTAT_TYPE_INT16:
		*(int16_t *)dst = ustat_get_i16(s, src);
		break;
	case USTAT_TYPE_INT32:
		*(int32_t *)dst = ustat_get_i32(s, src);
		break;
	case USTAT_TYPE_INT64:
		*(int64_t *)dst = ustat_get_i64(s, src);
		break;
	case USTAT_TYPE_UINT8:
		*(uint8_t *)dst = ustat_get_u8(s, src);
		break;
	case USTAT_TYPE_UINT16:
		*(uint16_t *)dst = ustat_get_u16(s, src);
		break;
	case USTAT_TYPE_UINT32:
		*(uint32_t *)dst = ustat_get_u32(s, src);
		break;
	case USTAT_TYPE_SIZE:
	case USTAT_TYPE_UINT64:
	case USTAT_TYPE_DELTA:
		*(uint64_t *)dst = ustat_get_u64(s, src);
		break;
	case USTAT_TYPE_CLOCK:
		ustat_get_clock(s, src, dst);
		break;
	case USTAT_TYPE_TOD:
		ustat_get_tod(s, src, dst);
		break;
	case USTAT_TYPE_STRING:
		(void) strncpy(*(char **)dst,
		ustat_get_str(s, src), src->usn_xlen);
		break;
	case USTAT_TYPE_BYTES:
		bcopy(ustat_get_bytes(s, src), *(uint8_t **)dst, src->usn_xlen);
		break;
	case USTAT_TYPE_ARRAY_U64:
		bcopy((void *)ustat_get_array_u64(s, src), *(uint64_t **)dst,
		    src->usn_xlen);
		break;
	case USTAT_TYPE_UUID:
		ustat_get_uuid(s, src, dst);
		break;
	case USTAT_TYPE_MAX:
		break;
	}
}

void
ustat_exportv(ustat_struct_t *s, int statc, ustat_struct_t *statv)
{
	ustat_group_t *g = USTAT_STRUCT_TO_GROUP(s);
	uint16_t i, n = MIN(statc, g->usg_statc);
	const ustat_named_t *src = g->usg_statv;
	ustat_named_t *dst = statv;

	for (i = 0; i < n; i++, src++, dst++) {
		if (src->usn_type == dst->usn_type && dst->usn_data != NULL)
			ustat_export(g->usg_statv, src, dst->usn_data);
	}
}

int
ustat_getnnames(ustat_struct_t *s)
{
	ustat_group_t *g = USTAT_STRUCT_TO_GROUP(s);

	return ((int)g->usg_statc);
}

ustat_named_t *
ustat_getprev(ustat_struct_t *s, ustat_named_t *n)
{
	ustat_group_t *g;
	ustat_page_t *p;

	if (s != NULL) {
		g = USTAT_STRUCT_TO_GROUP(s);
		p = USTAT_DATA_TO_PAGE(g->usg_handle, g);
	} else {
		p = ustat_page_lookup(n, sysconf(_SC_PAGESIZE));
		g = USTAT_PAGE_TO_DATA(p);
	}

	if (s == NULL || n == NULL || n == g->usg_statv)
		return (g->usg_statv);

	return (n - 1);
}

ustat_named_t *
ustat_getnext(ustat_struct_t *s, ustat_named_t *n)
{
	ustat_group_t *g = USTAT_STRUCT_TO_GROUP(s);

	if (n == NULL)
		return (g->usg_statv);

	if (n < g->usg_statv || n >= g->usg_statv + g->usg_statc - 1)
		return (NULL);

	return (n + 1);
}

const char *
ustat_getgname(ustat_struct_t *s)
{
	return (USTAT_STRUCT_TO_GROUP(s)->usg_gname);
}

const char *
ustat_getcname(ustat_struct_t *s)
{
	return (USTAT_STRUCT_TO_GROUP(s)->usg_cname);
}

void *
ustat_getprivate(ustat_struct_t *s)
{
	return (USTAT_STRUCT_TO_GROUP(s)->usg_uarg);
}

uint64_t
ustat_getctime(ustat_struct_t *s)
{
	return (USTAT_STRUCT_TO_GROUP(s)->usg_ctime);
}

uint64_t
ustat_getatime(ustat_struct_t *s)
{
	return (USTAT_STRUCT_TO_GROUP(s)->usg_atime);
}

void
ustat_getmbuf(ustat_struct_t *s, ustat_mbuf_t *m)
{
	ustat_group_t *g = USTAT_STRUCT_TO_GROUP(s);
	ustat_handle_t *h = g->usg_handle;
	ustat_page_t *p = USTAT_DATA_TO_PAGE(h, g);

	m->usm_data = p->usp_addr;
	m->usm_size = p->usp_size;
}

void
__attribute__ ((optimize("omit-frame-pointer")))
ustat_check_type(const ustat_struct_t *s, const ustat_named_t *n,
    ustat_type_t min_type, ustat_type_t max_type)
{
	if (n->usn_type < min_type || n->usn_type > max_type)
		ustat_caller_error(s, n, "ustat_check_type: invalid type");
}

void
__attribute__ ((optimize("omit-frame-pointer")))
ustat_atomic_set_clock(ustat_struct_t *s, ustat_named_t *n,
    const struct timespec *t)
{
	USTAT_CHECK_TYPE(s, n, USTAT_TYPE_CLOCK, USTAT_TYPE_CLOCK);
	ustat_atomic_set_u64(s, n, t->tv_sec * U_NANOSEC + t->tv_nsec);
}

void
__attribute__ ((optimize("omit-frame-pointer")))
ustat_set_clock(ustat_struct_t *s, ustat_named_t *n,
    const struct timespec *t)
{
	USTAT_CHECK_TYPE(s, n, USTAT_TYPE_CLOCK, USTAT_TYPE_CLOCK);
	ustat_set_u64(s, n, t->tv_sec * U_NANOSEC + t->tv_nsec);
}

void
__attribute__ ((optimize("omit-frame-pointer")))
ustat_atomic_set_tod(ustat_struct_t *s, ustat_named_t *n,
    const struct timeval *t)
{
	USTAT_CHECK_TYPE(s, n, USTAT_TYPE_TOD, USTAT_TYPE_TOD);
	ustat_atomic_set_u64(s, n, t->tv_sec * U_NANOSEC +
	    t->tv_usec * U_NANOSEC / U_MICROSEC);
}

void
__attribute__ ((optimize("omit-frame-pointer")))
ustat_set_tod(ustat_struct_t *s, ustat_named_t *n,
    const struct timeval *t)
{
	USTAT_CHECK_TYPE(s, n, USTAT_TYPE_TOD, USTAT_TYPE_TOD);
	ustat_set_u64(s, n, t->tv_sec * U_NANOSEC +
	    t->tv_usec * U_NANOSEC / U_MICROSEC);
}

void
__attribute__ ((optimize("omit-frame-pointer")))
ustat_set_string(ustat_struct_t *s, ustat_named_t *n, const char *str)
{
	ustat_value_t *v = n->usn_data;

	USTAT_CHECK_TYPE(s, n, USTAT_TYPE_STRING, USTAT_TYPE_STRING);
	v->usv_buf[n->usn_xlen - 1] = '\0';  /* stop reader overruns */
	(void) strncpy((char *)v->usv_buf, str, n->usn_xlen - 1);
}

void
__attribute__ ((optimize("omit-frame-pointer")))
ustat_set_bytes(ustat_struct_t *s, ustat_named_t *n, const uint8_t *buf,
    size_t len)
{
	ustat_value_t *v = n->usn_data;

	USTAT_CHECK_TYPE(s, n, USTAT_TYPE_BYTES, USTAT_TYPE_BYTES);
	bcopy(buf, v->usv_buf, MIN(len, n->usn_xlen));
}

void
__attribute__ ((optimize("omit-frame-pointer")))
ustat_set_array_u64(ustat_struct_t *s, ustat_named_t *n, const uint64_t *buf,
    size_t count)
{
	ustat_value_t *v = n->usn_data;

	USTAT_CHECK_TYPE(s, n, USTAT_TYPE_ARRAY_U64, USTAT_TYPE_ARRAY_U64);
	bcopy(buf, v->usv_buf, MIN(count * sizeof (uint64_t), n->usn_xlen));
}

void
__attribute__ ((optimize("omit-frame-pointer")))
ustat_set_uuid(ustat_struct_t *s, ustat_named_t *n, const uint8_t *u)
{
	ustat_value_t *v = n->usn_data;

	USTAT_CHECK_TYPE(s, n, USTAT_TYPE_UUID, USTAT_TYPE_UUID);
	(void) memcpy(v->usv_buf, u, MIN(n->usn_xlen, UU_UUID_BIN_LEN));
}

void
__attribute__ ((optimize("omit-frame-pointer")))
ustat_get_clock(ustat_struct_t *s, const ustat_named_t *n, struct timespec *t)
{
	uint64_t nsec = ustat_get_u64(s, n);

	USTAT_CHECK_TYPE(s, n, USTAT_TYPE_CLOCK, USTAT_TYPE_CLOCK);
	t->tv_sec = nsec / U_NANOSEC;
	t->tv_nsec = nsec % U_NANOSEC;
}

void
__attribute__ ((optimize("omit-frame-pointer")))
ustat_get_tod(ustat_struct_t *s, const ustat_named_t *n, struct timeval *t)
{
	uint64_t usec = ustat_get_u64(s, n) / (U_NANOSEC / U_MICROSEC);

	USTAT_CHECK_TYPE(s, n, USTAT_TYPE_TOD, USTAT_TYPE_TOD);
	t->tv_sec = usec / U_MICROSEC;
	t->tv_usec = usec % U_MICROSEC;
}

const char *
__attribute__ ((optimize("omit-frame-pointer")))
ustat_get_str(ustat_struct_t *s, const ustat_named_t *n)
{
	ustat_value_t *v = n->usn_data;

	USTAT_CHECK_TYPE(s, n, USTAT_TYPE_STRING, USTAT_TYPE_STRING);
	return ((const char *)v->usv_buf);
}

const uint8_t *
__attribute__ ((optimize("omit-frame-pointer")))
ustat_get_bytes(ustat_struct_t *s, const ustat_named_t *n)
{
	ustat_value_t *v = n->usn_data;

	USTAT_CHECK_TYPE(s, n, USTAT_TYPE_BYTES, USTAT_TYPE_BYTES);
	return (v->usv_buf);
}

const uint64_t *
__attribute__ ((optimize("omit-frame-pointer")))
ustat_get_array_u64(ustat_struct_t *s, const ustat_named_t *n)
{
	ustat_value_t *v = n->usn_data;

	USTAT_CHECK_TYPE(s, n, USTAT_TYPE_ARRAY_U64, USTAT_TYPE_ARRAY_U64);
	return (v->usv_buf_u64);
}

void
__attribute__ ((optimize("omit-frame-pointer")))
ustat_get_uuid(ustat_struct_t *s, const ustat_named_t *n, uint8_t *u)
{
	ustat_value_t *v = n->usn_data;

	USTAT_CHECK_TYPE(s, n, USTAT_TYPE_UUID, USTAT_TYPE_UUID);
	(void) memcpy(u, v->usv_buf, n->usn_xlen);
}

int
ustat_fprintf_unit(FILE *fp, int width,
    uint64_t value, const ustat_unit_t *unit)
{
	const char *s = "", *t;
	char buf[64];

	uint64_t u = 1;
	uint64_t v = value;

	if (unit == NULL)
		goto done;

	for (s = unit->usu_suff; v >= unit->usu_mult; s = t) {
		t = s + strlen(s) + 1;

		if (*t == '\0')
			break;

		u *= unit->usu_mult;
		v /= unit->usu_mult;
	}

done:
	if (unit == NULL || u == 1 || value % u == 0) {
		(void) snprintf(buf, sizeof (buf),
		    "%" PRIu64 "%s", v, s);
	} else {
		(void) snprintf(buf, sizeof (buf),
		    "%.1f%s", (double)value / u, s);
	}

	return (fprintf(fp, "%*s", width, buf));
}

static int
ustat_fprintf_clock(ustat_handle_t *h, FILE *fp,
    const ustat_named_t *n, const ustat_value_t *v)
{
	uint64_t sec = v->usv_u64 / U_NANOSEC;
	uint64_t nsec = v->usv_u64 % U_NANOSEC;

	if (sec != 0 && nsec == 0)
		return (fprintf(fp, "%" PRIu64 "s", sec));
	else if (sec == 0 && nsec != 0)
		return (fprintf(fp, "%" PRIu64 "ns", nsec));
	else
		return (fprintf(fp, "%" PRIu64 "s %" PRIu64 "ns", sec, nsec));
}

static int
ustat_sprintf_tod(const ustat_named_t *n, const ustat_value_t *v, char *str,
    size_t len)
{
	uint64_t tod = v->usv_u64 / (U_NANOSEC / U_MICROSEC);
	time_t sec = tod / U_MICROSEC;

	char buf[32];
	struct tm tm;

	if (localtime_r(&sec, &tm) != NULL &&
	    strftime(buf, sizeof (buf), "%FT%T", &tm) != 0)
		return (snprintf(str, len, "%s.%06llu", buf, tod % U_MICROSEC));
	else
		return (snprintf(str, len, "%" PRIu64, tod));
}

static int
ustat_fprintf_tod(ustat_handle_t *h, FILE *fp,
    const ustat_named_t *n, const ustat_value_t *v)
{
	char buf[256];

	(void) ustat_sprintf_tod(n, v, buf, sizeof (buf));
	buf[sizeof (buf) - 1] = '\0';
	return (fprintf(fp, "%s", buf));
}

static int
ustat_fprintf_bytes(ustat_handle_t *h, FILE *fp,
    const ustat_ifmt_t *f, const ustat_named_t *n, const ustat_value_t *v)
{
	int err, rv = 0;
	uint32_t i;

	if (n->usn_xlen != 0) {
		if ((err = fprintf(fp, f->usf_u8_first, v->usv_buf[0])) < 0)
			return (err);
		rv += err;
	}

	for (i = 1; i < n->usn_xlen; i++) {
		if ((err = fprintf(fp, f->usf_u8_rest, v->usv_buf[i])) < 0)
			return (err);
		rv += err;
	}

	return (rv);
}

static int
ustat_fprintf_array_u64(ustat_handle_t *h, FILE *fp,
    const ustat_ifmt_t *f, const ustat_named_t *n, const ustat_value_t *v)
{
	int err, rv = 0;
	uint32_t i;

	if (n->usn_xlen != 0) {
		if ((err = fprintf(fp, f->usf_u64_first,
		    v->usv_buf_u64[0])) < 0)
			return (err);
		rv += err;
	}

	for (i = 1; i < n->usn_xlen; i++) {
		if ((err = fprintf(fp, f->usf_u64_rest, v->usv_buf_u64[i])) < 0)
			return (err);
		rv += err;
	}

	return (rv);
}

static int
ustat_fprintf_uuid(ustat_handle_t *h, FILE *fp,
    const ustat_named_t *n, const ustat_value_t *v)
{
	char buf[UU_UUID_STR_LEN + 1];
#ifdef NOTYET
	uu_uuid_t u;
	(void) uu_uuid_from_bin(&u, v->usv_buf, n->usn_xlen);
	(void) uu_uuid_to_str(&u, buf, sizeof (buf));
#endif
	return (fprintf(fp, "%s", buf));
}

static const ustat_ifmt_t ustat_format_def = {
	"%" PRId8, "%" PRId16, "%" PRId32, "%" PRId64,
	"%" PRIu8, "%" PRIu16, "%" PRIu32, "%" PRIu64,
	"%02" PRIx8, ".%02" PRIx8, "%016" PRIx64, ".%016" PRIx64
};

static const ustat_ifmt_t ustat_format_oct = {
	"%" PRIo8, "%" PRIo16, "%" PRIo32, "%" PRIo64,
	"%" PRIo8, "%" PRIo16, "%" PRIo32, "%" PRIo64,
	"%02" PRIo8, ".%02" PRIo8, "%022" PRIo64, ".%022" PRIo64
};

static const ustat_ifmt_t ustat_format_dec = {
	"%" PRId8, "%" PRId16, "%" PRId32, "%" PRId64,
	"%" PRIu8, "%" PRIu16, "%" PRIu32, "%" PRIu64,
	"%" PRId8, ".%" PRId8, "%020" PRId64, ".%020" PRId64
};

static const ustat_ifmt_t ustat_format_hex = {
	"%" PRIx8, "%" PRIx16, "%" PRIx32, "%" PRIx64,
	"%" PRIx8, "%" PRIx16, "%" PRIx32, "%" PRIx64,
	"%02" PRIx8, ".%02" PRIx8, "%016" PRIx64, ".%016" PRIx64
};

int
ustat_fprintf(ustat_handle_t *h, FILE *fp, int radix, const ustat_named_t *n)
{
	ustat_value_t *v = n->usn_data;

	const ustat_ifmt_t *f;
	int err = -1;

	switch (radix) {
	case 0:
		f = &ustat_format_def;
		break;
	case 8:
		f = &ustat_format_oct;
		break;
	case 10:
		f = &ustat_format_dec;
		break;
	case 16:
		f = &ustat_format_hex;
		break;
	default:
		f = &ustat_format_dec;
		break;
	}

	switch (n->usn_type) {
	case USTAT_TYPE_INT8:
		err = fprintf(fp, f->usf_i8, v->usv_i8);
		break;
	case USTAT_TYPE_INT16:
		err = fprintf(fp, f->usf_i16, v->usv_i16);
		break;
	case USTAT_TYPE_INT32:
		err = fprintf(fp, f->usf_i32, v->usv_i32);
		break;
	case USTAT_TYPE_INT64:
		err = fprintf(fp, f->usf_i64, v->usv_i64);
		break;
	case USTAT_TYPE_UINT8:
		err = fprintf(fp, f->usf_u8, v->usv_u8);
		break;
	case USTAT_TYPE_UINT16:
		err = fprintf(fp, f->usf_u16, v->usv_u16);
		break;
	case USTAT_TYPE_UINT32:
		err = fprintf(fp, f->usf_u32, v->usv_u32);
		break;
	case USTAT_TYPE_UINT64:
		err = fprintf(fp, f->usf_u64, v->usv_u64);
		break;
	case USTAT_TYPE_SIZE:
		if (radix == 0)
			err = ustat_fprintf_unit(fp, 0,
			    v->usv_u64, &ustat_unit_size);
		else
			err = fprintf(fp, f->usf_u64, v->usv_u64);
		break;
	case USTAT_TYPE_CLOCK:
		if (radix == 0)
			err = ustat_fprintf_clock(h, fp, n, v);
		else
			err = fprintf(fp, f->usf_u64, v->usv_u64);
		break;
	case USTAT_TYPE_TOD:
		if (radix == 0)
			err = ustat_fprintf_tod(h, fp, n, v);
		else
			err = fprintf(fp, f->usf_u64, v->usv_u64);
		break;
	case USTAT_TYPE_DELTA:
		if (radix == 0)
			err = ustat_fprintf_unit(fp, 0,
			    v->usv_u64, &ustat_unit_time);
		else
			err = fprintf(fp, f->usf_u64, v->usv_u64);
		break;
	case USTAT_TYPE_STRING:
		err = fprintf(fp, "%s", v->usv_buf);
		break;
	case USTAT_TYPE_BYTES:
		err = ustat_fprintf_bytes(h, fp, f, n, v);
		break;
	case USTAT_TYPE_ARRAY_U64:
		err = ustat_fprintf_array_u64(h, fp, f, n, v);
		break;
	case USTAT_TYPE_UUID:
		err = ustat_fprintf_uuid(h, fp, n, v);
		break;
	case USTAT_TYPE_MAX:
		err = ustat_error(h, EINVAL, "invalid type: %u", n->usn_type);
	}

	return (err);
}

int
ustat_printf(ustat_handle_t *h, int radix, const ustat_named_t *n)
{
	return (ustat_fprintf(h, stdout, radix, n));
}

/*
 * Table of string names corresponding to ustat_type_t.  This needs to be kept
 * in sync with the set of enumerators in <ustat.h>.
 */
static const char *const ustat_typenames[USTAT_TYPE_MAX] = {
	"int8", "int16", "int32", "int64", "uint8", "uint16", "uint32",
	"uint64", "size", "clock", "tod", "delta", "string", "bytes",
	"array_u64", "uuid",
};

ustat_type_t
ustat_str2type(const char *s)
{
	ustat_type_t t;

	for (t = 0; t < USTAT_TYPE_MAX; t++) {
		if (strcasecmp(s, ustat_typenames[t]) == 0)
			return (t);
	}

	return (ustat_error(NULL, EINVAL, "invalid type name: %s", s));
}

const char *
ustat_type2str(ustat_type_t t)
{
	if (t >= USTAT_TYPE_MAX)
		return (ustat_null(NULL, EINVAL, "invalid type: %d", t));
	else
		return (ustat_typenames[t]);
}

/*
 * ustat bson elements are all of type "object", and have two children:
 *
 * "type": a bson string object which describes the type of the element, e.g.
 *         the ustat class or canonical type.
 *
 * "value": a bson object of type "type" which contains the data.
 *
 * Returns 0 on success, -1 on failure.  Sets *nd to the "value" offset on
 * success.
 */
static int
ustat_add_bson_elem(bson_t *b, off_t d, off_t *nd, const char *utype,
    const char *nname)
{
	off_t o = d;

	if (bson_exists(b, o, nname, &o, NULL))
		;
	else if (bson_add_object(b, o, nname, &o, bson_empty) != 0)
		return (-1);

	if (!bson_exists(b, o, "type", NULL, NULL)) {
		if (bson_add_string(b, o, "type", utype) != 0)
			return (-1);
	} else if (bson_set_string(b, o, "type", utype) != 0)
		return (-1);

	if (nd != NULL)
		*nd = o;

	return (0);
}

/*
 * Add a ustat bson object, which consists of type and value elements.
 * If 'nd' is not NULL, it is set to the offset of the 'value' element.
 */
int
ustat_set_bson_object(bson_t *b, off_t d, off_t *nd, const char *utype,
    const char *nname)
{
	off_t o = d;

	if (ustat_add_bson_elem(b, o, &o, utype, nname) != 0)
		return (-1);

	if (!bson_exists(b, o, "value", &o, NULL))
		if (bson_add_object(b, o, "value", &o, bson_empty) != 0)
			return (-1);

	if (nd != NULL)
		*nd = o;

	return (0);
}

/*
 * Adds a ustat group as a tree of bson objects, using '.' as the separator,
 * and handling the case where any/all bson objects already exist.  Returns 0
 * on success, -1 on failure.  nd is only modified on success.
 */
int
ustat_add_bson_group(ustat_struct_t *s, bson_t *b, off_t d, off_t *nd)
{
	const char *gname = ustat_getgname(s);
	const char *cname = ustat_getcname(s);
	const char *delim = ".";
	size_t slen = strlen(gname) + 1;
	char *str = alloca(slen);
	off_t o = d;
	char *q, *nextp;

	(void) memcpy(str, gname, slen);

	for (char *p = strtok_r(str, delim, &q); p != NULL; p = nextp) {
		nextp = strtok_r(NULL, delim, &q);

		if (ustat_set_bson_object(b, o, &o,
		    (nextp == NULL ? cname : "object"), p) != 0)
			return (-1);
	}

	if (nd != NULL)
		*nd = o;

	return (0);
}

int
ustat_set_bson_i64(bson_t *b, off_t d, const char *utype, const char *nname,
    int64_t val)
{
	off_t o = d;

	if (ustat_add_bson_elem(b, o, &o, utype, nname) != 0)
		return (-1);

	if (!bson_exists(b, o, "value", &o, NULL)) {
		if (bson_add_int64(b, o, "value", val) != 0)
			return (-1);
	} else if (bson_set_int64(b, o, "value", val) != 0)
		return (-1);

	return (0);
}

int
ustat_set_bson_str(bson_t *b, off_t d, const char *utype, const char *nname,
    const char *str)
{
	off_t o = d;

	if (ustat_add_bson_elem(b, o, &o, utype, nname) != 0)
		return (-1);

	if (!bson_exists(b, o, "value", &o, NULL)) {
		if (bson_add_string(b, o, "value", str) != 0)
			return (-1);
	} else if (bson_set_string(b, o, "value", str) != 0)
			return (-1);

	return (0);
}

int
ustat_set_bson_array(ustat_struct_t *s, bson_t *b, off_t d, off_t *nd,
    const char *utype, const char *nname)
{
	size_t ualen = strlen(utype) + 3;
	char *uaname = alloca(ualen);
	off_t o = d;

	(void) snprintf(uaname, ualen, "%s[]", utype);

	if (ustat_add_bson_elem(b, o, &o, uaname, nname) != 0)
		return (-1);

	if (!bson_exists(b, o, "value", &o, NULL))
		if (bson_add_array(b, o, "value", &o, bson_empty) != 0)
			return (-1);

	if (nd != NULL)
		*nd = o;

	return (0);
}

int
ustat_set_bson_cyctons(ustat_struct_t *s, bson_t *b, off_t d,
    ustat_named_t *n, uint64_t cycle_mult)
{
	const char *utype = ustat_type2str(n->usn_type);

	if (n->usn_type != USTAT_TYPE_UINT64)
		return (-1);

	return (ustat_set_bson_i64(b, d, utype, n->usn_name,
	    hrcyctonsm(ustat_get_u64(s, n), cycle_mult)));
}

int
ustat_export_bson(ustat_struct_t *s, const ustat_named_t *n, bson_t *b, off_t d)
{
	char uid_str[UU_UUID_STR_LEN+1];
	uint8_t uid_bin[UU_UUID_BIN_LEN];
	const char *nm = n->usn_name;
	const uint8_t *bytes;
	const uint64_t *array_u64;
	const char *ut = ustat_type2str(n->usn_type);
	struct timespec ts;
	char *str = NULL;
	int alen, used, elts;
	off_t o = d;

	if (ustat_add_bson_group(s, b, o, &o) != 0)
		return (-1);

	switch (n->usn_type) {
	case USTAT_TYPE_INT8:
		return (ustat_set_bson_i64(b, o, ut, nm, ustat_get_i8(s, n)));
	case USTAT_TYPE_INT16:
		return (ustat_set_bson_i64(b, o, ut, nm, ustat_get_i16(s, n)));
	case USTAT_TYPE_INT32:
		return (ustat_set_bson_i64(b, o, ut, nm, ustat_get_i32(s, n)));
	case USTAT_TYPE_INT64:
		return (ustat_set_bson_i64(b, o, ut, nm, ustat_get_i64(s, n)));
	case USTAT_TYPE_UINT8:
		return (ustat_set_bson_i64(b, o, ut, nm, ustat_get_u8(s, n)));
	case USTAT_TYPE_UINT16:
		return (ustat_set_bson_i64(b, o, ut, nm, ustat_get_u16(s, n)));
	case USTAT_TYPE_UINT32:
		return (ustat_set_bson_i64(b, o, ut, nm, ustat_get_u32(s, n)));
	case USTAT_TYPE_SIZE:
	case USTAT_TYPE_UINT64:
	case USTAT_TYPE_DELTA:
		return (ustat_set_bson_i64(b, o, ut, nm, ustat_get_u64(s, n)));
	case USTAT_TYPE_CLOCK:
		alen = 256;
		str = alloca(alen);
		ustat_get_clock(s, n, &ts);
		(void) snprintf(str, alen, "%" PRIu64 "s %" PRIu64 "ns",
		    (uint64_t)ts.tv_sec, (uint64_t)ts.tv_nsec);
		str[alen-1] = '\0';
		return (ustat_set_bson_str(b, o, ut, nm, str));
	case USTAT_TYPE_TOD:
		alen = 256;
		str = alloca(alen);
		(void) ustat_sprintf_tod(s, n->usn_data, str, alen);
		str[alen-1] = '\0';
		return (ustat_set_bson_str(b, o, ut, nm, str));
	case USTAT_TYPE_STRING:
		return (ustat_set_bson_str(b, o, ut, nm, ustat_get_str(s, n)));
	case USTAT_TYPE_BYTES:
		bytes = ustat_get_bytes(s, n);
		elts = n->usn_xlen;
		alen = (elts * 3) + 1;
		str = alloca(alen);
		str[0] = 0;
		used = 0;
		if (elts > 0 && used < alen)
			used += snprintf(str + used, alen - used,
			    ustat_format_def.usf_u8_first, bytes[0]);
		for (int i = 1; i < elts && used < alen; i++)
			used += snprintf(str + used, alen - used,
			    ustat_format_def.usf_u8_rest, bytes[i]);

		return (ustat_set_bson_str(b, o, ut, nm, str));
	case USTAT_TYPE_ARRAY_U64:
		array_u64 = ustat_get_array_u64(s, n);
		elts = n->usn_xlen / sizeof (uint64_t);
		alen = (elts * 17) + 1;
		str = alloca(alen);
		str[0] = 0;
		used = 0;
		if (elts > 0 && used < alen)
			used += snprintf(str + used, alen - used,
			    ustat_format_def.usf_u64_first, array_u64[0]);
		for (int i = 1; i < elts && used < alen; i++)
			used += snprintf(str + used, alen - used,
			    ustat_format_def.usf_u64_rest, array_u64[i]);
		return (ustat_set_bson_str(b, o, ut, nm, str));
	case USTAT_TYPE_UUID:
		ustat_get_uuid(s, n, uid_bin);
#ifdef NOTYET
		if (uu_uuid_to_str(&uid, uid_str, UU_UUID_STR_LEN) ==
		    UU_UUID_STR_LEN) {
			uid_str[UU_UUID_STR_LEN] = '\0';
			return (ustat_set_bson_str(b, o, ut, nm, uid_str));
		}
#endif
		break;
	case USTAT_TYPE_MAX:
		break;
	}

	return (-1);
}

/* Exports a ustat struct to BSON using the ustat misc class */
static int
ustat_misc_export_bson(ustat_struct_t *s, int statc, bson_t *b, off_t d)
{
	ustat_group_t *g = USTAT_STRUCT_TO_GROUP(s);
	uint16_t i, n = MIN(statc, g->usg_statc);
	const ustat_named_t *src = g->usg_statv;

	for (i = 0; i < n; i++, src++)
		if (ustat_export_bson(g->usg_statv, src, b, d) != 0)
			return (-1);

	return (0);
}

/* Exports a ustat struct to BSON */
int
ustat_exportv_bson(ustat_struct_t *s, int statc, bson_t *b, off_t d)
{
	ustat_group_t *g = USTAT_STRUCT_TO_GROUP(s);
	const ustat_class_t *uc = ustat_cname_to_class(g->usg_cname);
	ustat_export_bson_t export_bson;

	if (uc->usc_bson != NULL)
		export_bson = uc->usc_bson;
	else
		export_bson = ustat_class_misc.usc_bson;

	/*
	 * allow bson export without detailed knowledge of a ustat's
	 * internal size or structure
	 */
	if (uc != &ustat_class_misc)
		statc = 0;

	return (export_bson(s, statc, b, d));
}
