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

#ifndef _USTAT_IO_H
#define	_USTAT_IO_H

#include <ustat.h>

#ifdef	__cplusplus
extern "C" {
#endif

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
 * There are three basic abstractions managed by these functions:
 * ustat_io_t - accumulated i/o stats for a subsystem
 * ustat_iop_t - i/o stats for a single i/o operation
 * ustat_io_delta_t - derived i/o stats from the delta between two ustat_io_t's
 */

typedef struct ustat_io {
	ustat_named_t uio_reads;	/* number of read ops */
	ustat_named_t uio_rbytes;	/* number of read bytes */
	ustat_named_t uio_writes;	/* number of write ops */
	ustat_named_t uio_wbytes;	/* number of write bytes */
	ustat_named_t uio_cbytes;	/* number of copy bytes */
	ustat_named_t uio_wtime;	/* time accumulated in wait queue */
	ustat_named_t uio_rtime;	/* time accumulated in run queue */
	ustat_named_t uio_ttime;	/* time accumulated by all i/o's */
	ustat_named_t uio_utime;	/* time recorded at last update */
	ustat_named_t uio_errors;	/* number of failed ops */
	ustat_named_t uio_total;	/* number of total ops */
	ustat_named_t uio_ctons;	/* conversion for hrcyctonsm() */
} ustat_io_t;

typedef struct ustat_iop {
	uint64_t uiop_init;		/* i/o init time (waitq enter) */
	uint64_t uiop_exec;		/* i/o exec time (waitq-to-runq) */
	uint64_t uiop_fini;		/* i/o fini time (runq exit) */
	uint32_t uiop_rlen;		/* i/o read length in bytes */
	uint32_t uiop_wlen;		/* i/o write length in bytes */
	uint32_t uiop_clen;		/* i/o copy length in bytes */
	uint32_t uiop_errs;		/* i/o errors encountered */
} ustat_iop_t;

typedef struct ustat_io_delta {
	double uiod_delta;		/* delta time in seconds */
	uint64_t uiod_t_iops;		/* total iops */
	uint64_t uiod_r_iops;		/* read iops */
	uint64_t uiod_w_iops;		/* write iops */
	uint64_t uiod_r_bw;		/* read bytes / sec */
	uint64_t uiod_w_bw;		/* write bytes / sec */
	uint64_t uiod_c_bw;		/* copy bytes / sec */
	double uiod_avgw_us;		/* avg wait usec / iop */
	double uiod_avgr_us;		/* avg run usec / iop */
	double uiod_avgt_us;		/* avg total usec / iop */
} ustat_io_delta_t;

extern const ustat_class_t ustat_class_io;
extern const ustat_iop_t ustat_iop_failed;

extern void ustat_io_enter(ustat_io_t *, const ustat_iop_t *);
extern void ustat_io_delta(ustat_io_t *, ustat_io_delta_t *);
extern void ustat_io_stats(uint64_t, ustat_io_t *, ustat_io_delta_t *);
extern void ustat_io_merge(ustat_io_t *, const ustat_io_t *);
extern void ustat_io_reset(ustat_io_t *);

#ifdef	__cplusplus
}
#endif

#endif	/* _USTAT_IO_H */
