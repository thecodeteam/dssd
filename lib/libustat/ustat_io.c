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
 * Userland Statistics I/O Class
 *
 * Typical i/o subsystems have two basic queues of transactions they manage:
 * one for transactions that have been accepted for processing but for which
 * processing has yet to begin, and one for transactions which are actively
 * being processed but not yet done.  The ustat_io_ functions manage a ustat
 * group that tracks the activity of these type of i/o subsystems, including
 * the wait (pre-service) time, the run (service) time, IOPS, and bandwidth.
 *
 * The operations supported here are:
 *
 * ustat_io_enter - enter one i/o statistic record into the collection
 * ustat_io_delta - compute the averages and per-second ops between snapshots
 * ustat_io_stats - compute the averages and per-second ops since a known time
 * ustat_io_merge - merge one statistics collection with another collection
 * ustat_io_reset - reset the statistics collection
 */

#include <sys/param.h>
#include <errno.h>

#include <units.h>
#include <hrtime.h>
#include <ustat_io.h>
#include <ustat_impl.h>

const ustat_iop_t ustat_iop_failed = { .uiop_errs = 1 };

/*
 * Atomically add 'delta' to the specified 64-bit statistic counter.
 */
static inline void
__attribute__((always_inline))
ustat_io_add_u64(ustat_named_t *n, uint64_t delta)
{
	ustat_value_t *v = n->usn_data;
	(void) __sync_fetch_and_add(&v->usv_u64, delta);
}

/*
 * Atomically set a 'new' clock value, making sure the clock is always advancing
 * such that races between iop completions cannot decrement the clock.
 */
static inline void
__attribute__((always_inline))
ustat_io_set_clock(ustat_named_t *n, uint64_t new)
{
	ustat_value_t *v = n->usn_data;
	uint64_t *vp = &v->usv_u64;

	for (uint64_t old = *vp; new > old; old = *vp) {
		if (__sync_val_compare_and_swap(vp, old, new) == old)
			break;
	}
}

/*
 * Enter the statistics for a completed i/o operation into the accumulated i/o
 * statistics.  The caller is responsible for filling in ustat_iop_t members.
 */
void
ustat_io_enter(ustat_io_t *uio, const ustat_iop_t *uiop)
{
	if (uiop->uiop_rlen != 0) {
		ustat_io_add_u64(&uio->uio_reads, 1);
		ustat_io_add_u64(&uio->uio_rbytes, uiop->uiop_rlen);
	}

	if (uiop->uiop_wlen != 0) {
		ustat_io_add_u64(&uio->uio_writes, 1);
		ustat_io_add_u64(&uio->uio_wbytes, uiop->uiop_wlen);
	}

	if (uiop->uiop_clen != 0)
		ustat_io_add_u64(&uio->uio_cbytes, uiop->uiop_clen);

	ustat_io_add_u64(&uio->uio_wtime, uiop->uiop_exec - uiop->uiop_init);
	ustat_io_add_u64(&uio->uio_rtime, uiop->uiop_fini - uiop->uiop_exec);
	ustat_io_add_u64(&uio->uio_ttime, uiop->uiop_fini - uiop->uiop_init);
	ustat_io_set_clock(&uio->uio_utime, uiop->uiop_fini);

	if (uiop->uiop_errs != 0)
		ustat_io_add_u64(&uio->uio_errors, uiop->uiop_errs);

	ustat_io_add_u64(&uio->uio_total, 1);
}

static const ustat_io_t ustat_io_template = {
	{ "reads", USTAT_TYPE_UINT64, 0, NULL },
	{ "rbytes", USTAT_TYPE_SIZE, 0, NULL },
	{ "writes", USTAT_TYPE_UINT64, 0, NULL },
	{ "wbytes", USTAT_TYPE_SIZE, 0, NULL },
	{ "cbytes", USTAT_TYPE_SIZE, 0, NULL },
	{ "wtime", USTAT_TYPE_UINT64, 0, NULL },
	{ "rtime", USTAT_TYPE_UINT64, 0, NULL },
	{ "ttime", USTAT_TYPE_UINT64, 0, NULL },
	{ "utime", USTAT_TYPE_UINT64, 0, NULL },
	{ "errors", USTAT_TYPE_UINT64, 0, NULL },
	{ "total", USTAT_TYPE_UINT64, 0, NULL },
	{ "ctons", USTAT_TYPE_UINT32, 0, NULL },
};

static ustat_struct_t *
ustat_io_ctor(ustat_handle_t *h, const char *ename, const char *gname,
    int statc, const ustat_struct_t *statv, void *uarg)
{
	ustat_struct_t *s;

	if (statc != 0) {
		return (ustat_null(h, EINVAL, "invalid statc for class_io: "
		    "got %d, expected zero", statc));
	}

	if (statv != NULL) {
		return (ustat_null(h, EINVAL, "invalid statv for class_io: "
		    "got %p, expected NULL", (void *)statv));
	}

	s = ustat_insert(h, ename, gname, &ustat_class_io,
	    sizeof (ustat_io_template) / sizeof (ustat_named_t),
	    &ustat_io_template, uarg);

	if (s != NULL)
		ustat_io_reset(s);

	return (s);
}

static int
ustat_io_dtor(ustat_handle_t *h, void *carg)
{
	return (0);
}

/* Export a ustat_io instance to BSON. */
static int
ustat_io_export_bson(ustat_struct_t *s, int statc, bson_t *b, off_t d)
{
	ustat_io_t *uio = s;
	uint32_t ctons;
	int ret = 0;
	off_t o = d;

	if (statc != 0 && statc != sizeof (ustat_io_t) / sizeof (ustat_named_t))
		return (-1);

	ctons = ustat_get_u32(uio, &uio->uio_ctons);

	if (ustat_add_bson_group(s, b, o, &o) != 0)
		return (-1);

	ret |= ustat_export_bson(uio, &uio->uio_reads, b, d);
	ret |= ustat_export_bson(uio, &uio->uio_rbytes, b, d);
	ret |= ustat_export_bson(uio, &uio->uio_writes, b, d);
	ret |= ustat_export_bson(uio, &uio->uio_wbytes, b, d);
	ret |= ustat_export_bson(uio, &uio->uio_cbytes, b, d);

	ret |= ustat_set_bson_cyctons(s, b, o, &uio->uio_wtime, ctons);
	ret |= ustat_set_bson_cyctons(s, b, o, &uio->uio_rtime, ctons);
	ret |= ustat_set_bson_cyctons(s, b, o, &uio->uio_ttime, ctons);
	ret |= ustat_set_bson_cyctons(s, b, o, &uio->uio_utime, ctons);

	ret |= ustat_export_bson(uio, &uio->uio_errors, b, d);
	ret |= ustat_export_bson(uio, &uio->uio_total, b, d);

	return (ret);
}


const ustat_class_t ustat_class_io = {
	.usc_name = "io",
	.usc_ctor = ustat_io_ctor,
	.usc_dtor = ustat_io_dtor,
	.usc_bson = ustat_io_export_bson,
};

#define	USTAT_IO_DELTA(old, new, item) \
	(old ? ustat_get_u64(new, &new->item) - \
	ustat_get_u64(old, &old->item) : ustat_get_u64(new, &new->item))

#define	USTAT_IO_AVGUS(nsec, cmds) \
	(cmds ? (double)(nsec) / (double)(cmds) / \
	(FP_NANOSEC / FP_MICROSEC) : 0.0)

/*
 * Take the specified ustat_io_t snapshots and a time interval 'd', and
 * then perform the math for the common statistics one might want to see.
 * These statistics are derived as follows:
 *
 * total iops = delta(uio_total) / seconds
 * read iops = delta(uio_reads) / seconds
 * write iops = delta(uio_writes) / seconds
 * read b/w = delta(uio_rbytes) / seconds
 * write b/w = delta(uio_wbytes) / seconds
 * copy b/w = delta(uio_cbytes) / seconds
 * avg_w us = delta(uio_wtime) / delta(uio_total) / (ns / us)
 * avg_r us = delta(uio_rtime) / delta(uio_total) / (ns / us)
 * avg_t us = delta(uio_ttime) / delta(uio_total) / (ns / us)
 */
static void
ustat_io_delta_calc(ustat_io_t *uio0, ustat_io_t *uio1,
    uint64_t d, ustat_io_delta_t *uiod)
{
	uint32_t ctons = ustat_get_u32(uio1, &uio1->uio_ctons);

	double t_s, t_ns;
	uint64_t t;

	if (d != 0) {
		t_ns = (double)d;
		uiod->uiod_delta = t_s = t_ns / FP_NANOSEC;
	} else {
		t_ns = FP_NANOSEC;
		uiod->uiod_delta = t_s = FP_SEC;
	}

	t = USTAT_IO_DELTA(uio0, uio1, uio_total);
	uiod->uiod_t_iops = (uint64_t)((double)t / t_s);

	d = USTAT_IO_DELTA(uio0, uio1, uio_reads);
	uiod->uiod_r_iops = (uint64_t)((double)d / t_s);

	d = USTAT_IO_DELTA(uio0, uio1, uio_writes);
	uiod->uiod_w_iops = (uint64_t)((double)d / t_s);

	d = USTAT_IO_DELTA(uio0, uio1, uio_rbytes);
	uiod->uiod_r_bw = (uint64_t)((double)d / t_s);

	d = USTAT_IO_DELTA(uio0, uio1, uio_wbytes);
	uiod->uiod_w_bw = (uint64_t)((double)d / t_s);

	d = USTAT_IO_DELTA(uio0, uio1, uio_cbytes);
	uiod->uiod_c_bw = (uint64_t)((double)d / t_s);

	d = USTAT_IO_DELTA(uio0, uio1, uio_wtime);
	d = hrcyctonsm(d, ctons);
	uiod->uiod_avgw_us = USTAT_IO_AVGUS(d, t);

	d = USTAT_IO_DELTA(uio0, uio1, uio_rtime);
	d = hrcyctonsm(d, ctons);
	uiod->uiod_avgr_us = USTAT_IO_AVGUS(d, t);

	d = USTAT_IO_DELTA(uio0, uio1, uio_ttime);
	d = hrcyctonsm(d, ctons);
	uiod->uiod_avgt_us = USTAT_IO_AVGUS(d, t);
}

void
ustat_io_delta(ustat_io_t *uio1, ustat_io_delta_t *uiod)
{
	ustat_io_t *uio0;
	uint64_t d;

	if ((uio0 = ustat_previous(uio1)) != NULL)
		d = ustat_getatime(uio1) - ustat_getatime(uio0);
	else
		d = ustat_getatime(uio1) - ustat_getctime(uio1);

	ustat_io_delta_calc(uio0, uio1, d, uiod);
}

void
ustat_io_stats(uint64_t t0, ustat_io_t *uio1, ustat_io_delta_t *uiod)
{
	uint64_t utime = ustat_get_u64(uio1, &uio1->uio_utime);
	uint32_t ctons = ustat_get_u32(uio1, &uio1->uio_ctons);

	ustat_io_delta_calc(NULL, uio1, hrcyctonsm(utime - t0, ctons), uiod);
}

#define	USTAT_IO_MERGE(dst, src, st) \
	ustat_add_u64(dst, &dst->st, \
	    ustat_get_u64((ustat_struct_t *)src, &src->st))

void
ustat_io_merge(ustat_io_t *dst, const ustat_io_t *src)
{
	uint64_t t_dst, t_src;

	USTAT_IO_MERGE(dst, src, uio_reads);
	USTAT_IO_MERGE(dst, src, uio_rbytes);
	USTAT_IO_MERGE(dst, src, uio_writes);
	USTAT_IO_MERGE(dst, src, uio_wbytes);
	USTAT_IO_MERGE(dst, src, uio_cbytes);

	USTAT_IO_MERGE(dst, src, uio_wtime);
	USTAT_IO_MERGE(dst, src, uio_rtime);
	USTAT_IO_MERGE(dst, src, uio_ttime);

	t_src = ustat_get_u64((ustat_struct_t *)src, &src->uio_utime);
	t_dst = ustat_get_u64((ustat_struct_t *)dst, &dst->uio_utime);
	ustat_set_u64(dst, &dst->uio_utime, MAX(t_src, t_dst));

	USTAT_IO_MERGE(dst, src, uio_errors);
	USTAT_IO_MERGE(dst, src, uio_total);
}

void
ustat_io_reset(ustat_io_t *uio)
{
	ustat_atomic_clr_u64(uio, &uio->uio_reads);
	ustat_atomic_clr_u64(uio, &uio->uio_rbytes);
	ustat_atomic_clr_u64(uio, &uio->uio_writes);
	ustat_atomic_clr_u64(uio, &uio->uio_wbytes);
	ustat_atomic_clr_u64(uio, &uio->uio_cbytes);

	ustat_atomic_clr_u64(uio, &uio->uio_wtime);
	ustat_atomic_clr_u64(uio, &uio->uio_rtime);
	ustat_atomic_clr_u64(uio, &uio->uio_ttime);
	ustat_atomic_clr_u64(uio, &uio->uio_utime);

	ustat_atomic_clr_u64(uio, &uio->uio_errors);
	ustat_atomic_clr_u64(uio, &uio->uio_total);

	ustat_atomic_set_u32(uio, &uio->uio_ctons, gethrcycle_mult());
}
