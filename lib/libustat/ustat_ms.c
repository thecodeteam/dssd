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
 * Userland Statistics Microstate Class
 *
 * This class provides the ability to quantize operations that have microstate
 * accounting data into power-of-two buckets, and then display two-dimensional
 * analysis of their time distribution, and work distribution by microstate.
 * This is a more specialized form of the generic ustat_hg histogram.
 *
 * The basic idea here is that we are recording cycles spent per-state per-io.
 * We then want to organize the i/o's by their total latency in a histogram,
 * and then break down the rows of that histogram by state, in order to answer
 * the question: if an i/o was slow, where did it spend the majority of time?
 *
 * The implementation here is that we take a ustat page, alloc a few metadata
 * elements, and then a dynamically-sized array of stats for [ rows x cols ],
 * where the rows are the histogram latency buckets, and the columns are the
 * microstates.  The creator of the ustat is responsible for giving us a
 * microstate 'specification' describing the grid size and state names, so that
 * we keep the knowledge of states isolated to the consuming program, and also
 * to permit that program to have multiple kinds of microstate-aware objects.
 */

#include <hrtime.h>
#include <units.h>

#include <alloca.h>
#include <bson.h>
#include <limits.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <math.h>
#include <vmem.h>

#include <ustat_impl.h>

#include <ustat_hg.h>
#include <ustat_ms.h>

#define	USTAT_MS_NLEN	7	/* name length of "rNNcNN\0" */

typedef struct ustat_ms_plot {
	uint8_t usmp_mag1;		/* magic header bytes */
	uint8_t usmp_mag2;		/* magic header bytes */
	uint8_t usmp_rows;		/* rows / time buckets */
	uint8_t usmp_cols;		/* cols / microstates */
	uint32_t usmp_ctons;		/* cycle to ns for hrcyctonsm() */
	uint64_t usmp_stats[1];		/* rows * cols encoded histogram */
} ustat_ms_plot_t;

/*
 * Microstate constructor.  This constructor can be passed the definition
 * via statc and statv (in which case it's a ustat_ms_t + row/col def.),
 * or via uarg (in which case uarg points to a ustat_ms_spec_t.)
 */
static ustat_struct_t *
ustat_ms_ctor(ustat_handle_t *h, const char *ename, const char *gname,
    int statc, const ustat_struct_t *statv, void *uarg)
{
	int ms_nnamed = sizeof (ustat_ms_t) / sizeof (ustat_named_t);
	ustat_ms_spec_t *msp = uarg;

	ustat_ms_t *m;
	ustat_named_t *n;
	size_t rows, cols, len1, len2;
	char *p, *buf1, *buf2;

	if (statc >= ms_nnamed && statv != NULL)
		goto done;

	if (statc != 0) {
		return (ustat_null(h, EINVAL, "invalid statc for class_ms: "
		    "got %d, expected zero", statc));
	}

	if (statv != NULL) {
		return (ustat_null(h, EINVAL, "invalid statv for class_ms: "
		    "got %p, expected NULL", (void *)statv));
	}

	rows = msp->usms_rows;
	cols = msp->usms_cols;

	statc = ms_nnamed + rows * cols - 1;
	statv = alloca(sizeof (ustat_named_t) * statc);

	m = (ustat_ms_t *)statv;
	n = m->usms_stats;

	len1 = 0;
	for (size_t c = 0; c < cols; c++)
		len1 += strlen(msp->usms_names[c]) + 1;

	p = buf1 = alloca(len1);
	for (size_t c = 0; c < cols; c++, p += strlen(p) + 1)
		(void) strcpy(p, msp->usms_names[c]);

	len2 = rows * cols * USTAT_MS_NLEN;
	p = buf2 = alloca(len2);

	m->usms_nrows.usn_name = "nrows";
	m->usms_nrows.usn_type = USTAT_TYPE_UINT8;
	m->usms_nrows.usn_xlen = 0;
	m->usms_nrows.usn_data = &msp->usms_rows;

	m->usms_ncols.usn_name = "ncols";
	m->usms_ncols.usn_type = USTAT_TYPE_UINT8;
	m->usms_ncols.usn_xlen = 0;
	m->usms_ncols.usn_data = &msp->usms_cols;

	m->usms_names.usn_name = "names";
	m->usms_names.usn_type = USTAT_TYPE_BYTES;
	m->usms_names.usn_xlen = len1;
	m->usms_names.usn_data = &buf1;

	m->usms_ctons.usn_name = "ctons";
	m->usms_ctons.usn_type = USTAT_TYPE_UINT32;
	m->usms_ctons.usn_xlen = 0;
	m->usms_ctons.usn_data = &msp->usms_ctons;

	for (size_t r = 0; r < rows; r++) {
		for (size_t c = 0; c < cols; c++, n++, p += USTAT_MS_NLEN) {
			(void) snprintf(p, USTAT_MS_NLEN, "r%02zuc%02zu", r, c);
			n->usn_name = p;
			n->usn_type = USTAT_TYPE_UINT64;
			n->usn_xlen = 0;
			n->usn_data = NULL;
		}
	}

done:
	return (ustat_insert(h, ename, gname,
	    &ustat_class_ms, statc, statv, uarg));
}

static int
ustat_ms_dtor(ustat_handle_t *h, void *carg)
{
	return (0);
}

/* Export a ustat_ms instance to BSON. */
static int
ustat_ms_export_bson(ustat_struct_t *s, int statc, bson_t *b, off_t d)
{
	ustat_ms_t *ms = s;
	const char *names, *name;
	uint8_t nrows, ncols;
	ustat_named_t *cs;
	uint64_t cnt = 0;
	off_t o = d;
	off_t ro, rao, so;
	uint32_t ctons;
	char buf[64];
	int ret = 0;

	if (statc != 0 && statc != sizeof (ustat_ms_t) / sizeof (ustat_named_t))
		return (-1);

	ncols = ustat_get_u8(ms, &ms->usms_ncols);
	nrows = ustat_get_u8(ms, &ms->usms_nrows);
	ctons = ustat_get_u32(ms, &ms->usms_ctons);
	names = (const char *)ustat_get_bytes(ms, &ms->usms_names);

	if (nrows == 0 || ncols == 0)
		return (0);

	if (ustat_add_bson_group(s, b, o, &o) != 0)
		return (-1);

	/*
	 * Add the column names.  The first column in the source is always a
	 * count, which is written separately from the other columns to BSON.
	 */
	if (ustat_set_bson_array(s, b, o, &so,
	    ustat_type2str(USTAT_TYPE_STRING), "col_names") != 0)
		return (-1);

	name = names + strlen(names) + 1;  /* skip count column */
	for (unsigned i = 1; i < ncols; i++) {
		(void) snprintf(buf, sizeof (buf), "%u", i - 1);
		ret |= bson_add_string(b, so, buf, name);
		name += strlen(name) + 1;
	}

	/* Add the row bins (stored in us, but written to BSON in ns) */
	if (ustat_set_bson_array(s, b, o, &so,
	    ustat_type2str(USTAT_TYPE_DELTA), "bins") != 0)
		return (-1);

	for (unsigned r = 0; r < nrows; r++) {
		(void) snprintf(buf, sizeof (buf), "%u", r);

		if (bson_add_int64(b, so, buf, (r == 0 ? 0 :
		    (1ull << (r - 1)) * (U_NANOSEC / U_MICROSEC))) != 0)
			return (-1);
	}

	/* Add the stats as a 2D array */
	if (ustat_set_bson_array(s, b, o, &so, "", "stats") != 0)
		return (-1);

	cs = ms->usms_stats;
	for (unsigned r = 0; r < nrows; r++) {
		(void) snprintf(buf, sizeof (buf), "%u", r);

		if (ustat_set_bson_object(b, so, &ro, "object", buf) != 0)
			return (-1);

		/* Column 0 contains the total count for the row */
		cnt = ustat_get_u64(ms, cs++);
		if (ustat_set_bson_i64(b, ro, ustat_type2str(USTAT_TYPE_UINT64),
		    "count", cnt) != 0)
			return (-1);

		if (ustat_set_bson_array(s, b, ro, &rao,
		    ustat_type2str(USTAT_TYPE_DELTA), "cols") != 0)
			return (-1);

		for (unsigned c = 1; c < ncols; c++) {
			uint64_t tot = hrcyctonsm(ustat_get_u64(ms, cs), ctons);
			uint64_t avg = cnt ? tot / cnt : 0;

			cs++;
			(void) snprintf(buf, sizeof (buf), "%u", c - 1);
			if (bson_add_int64(b, rao, buf, avg) != 0)
				return (-1);
		}
	}

	return (ret);
}

const ustat_class_t ustat_class_ms = {
	.usc_name = "ms",
	.usc_ctor = ustat_ms_ctor,
	.usc_dtor = ustat_ms_dtor,
	.usc_bson = ustat_ms_export_bson,
};

static inline void
__attribute__((always_inline))
ustat_ms_uint64_add(ustat_named_t *n, uint64_t delta)
{
	ustat_value_t *v = n->usn_data;
	(void) __sync_fetch_and_add(&v->usv_u64, delta);
}

/*
 * Add a new set of columns from an i/o to the microstate histogram.  To do
 * this, we take colv[0] (the total i/o time) and use that to select a latency
 * bin.  Then we bump the bin count by one, and add in the remaining columns.
 */
void
ustat_ms_enter(ustat_ms_t *ms, ustat_ms_spec_t *msp, const uint64_t *colv)
{
	ustat_named_t *n;
	uint8_t r, c;

	uint64_t ns = hrcyctonsm(colv[0], msp->usms_ctons);
	uint64_t us = ns / (U_NANOSEC / U_MICROSEC);

	r = ustat_hg_bin64(us);
	r = r <= msp->usms_rows - 1 ? r : msp->usms_rows - 1;
	n = &ms->usms_stats[r * msp->usms_cols];

	ustat_ms_uint64_add(n++, 1);

	for (c = 1; c < msp->usms_cols; c++, n++)
		ustat_ms_uint64_add(n, colv[c]);
}

/*
 * Print the grid values in a 'raw' format, suitable for input to gnuplot.
 * In this format, we just space-delimit the values and include the TIME bin,
 * COUNT, and a calculated percentage as the initial columns.  For the
 * remaining state columns, we convert cycles to nanoseconds and then divide
 * by that row's count, thereby computing the average ns per state per bin.
 */
void
ustat_ms_printx(ustat_ms_spec_t *msp, const uint64_t *vp, FILE *fp)
{
	double *pct = alloca(sizeof (double) * msp->usms_rows);

	uint64_t cnt = 0;
	uint64_t sum = 0;

	for (size_t r = 0; r < msp->usms_rows; r++)
		sum += vp[r * msp->usms_cols];

	if (sum == 0)
		sum = 1;

	for (size_t r = 0; r < msp->usms_rows; r++)
		pct[r] = (double)vp[r * msp->usms_cols] / (double)sum * 100.0;

	(void) fprintf(fp, "%s %s %s", "TIME", "PCT", "COUNT");
	for (size_t c = 1; c < msp->usms_cols; c++)
		(void) fprintf(fp, " %s", msp->usms_names[c]);
	(void) fprintf(fp, "\n");

	for (size_t r = 0; r < msp->usms_rows; r++) {
		if (r + 1 != (size_t)msp->usms_rows) {
			(void) fprintf(fp, "%llu-%lluus %.1f",
			    r ? 1ull << (r - 1) : 0, 1ull << r, pct[r]);
		} else {
			(void) fprintf(fp, "%llu+us %.1f",
			    r ? 1ull << (r - 1) : 0, pct[r]);
		}

		if (msp->usms_cols != 0) {
			cnt = *vp++;
			(void) fprintf(fp, " %ju", cnt);
		}

		for (size_t c = 1; c < msp->usms_cols; c++) {
			uint64_t cy = *vp++;
			uint64_t ns = hrcyctonsm(cy, msp->usms_ctons);
			double us = (double)ns / (FP_NANOSEC / FP_MICROSEC);

			if (cnt == 0)
				(void) fprintf(fp, " %.2fu", 0.0);
			else
				(void) fprintf(fp, " %.2fu", us / cnt);
		}

		(void) fprintf(fp, "\n");
	}
}

/*
 * Print the grid values in human-readable form, suitable for output to a tty.
 * In this format, we try to size the columns to line up nicely, include units
 * of either u (usec) or s (sec), and calculate each column as an average.
 */
void
ustat_ms_printv(ustat_ms_spec_t *msp, const uint64_t *vp, FILE *fp)
{
	const int width = 9;
	uint64_t cnt = 0;

	(void) fprintf(fp, "%4s%*s", "TIME", width, "COUNT");
	for (size_t c = 1; c < msp->usms_cols; c++)
		(void) fprintf(fp, "%*s", width, msp->usms_names[c]);
	(void) fprintf(fp, "\n");

	for (size_t r = 0; r < msp->usms_rows; r++) {
                if (r == 0)
                        (void) fprintf(fp, "%4s", "0");
		else
			(void) fprintf(fp, "%2lluus", 1ull << (r - 1));

		if (msp->usms_cols != 0)
			(void) fprintf(fp, "%*ju", width, cnt = *vp++);

		for (size_t c = 1; c < msp->usms_cols; c++) {
			uint64_t tot = hrcyctonsm(*vp++, msp->usms_ctons);
			uint64_t avg = cnt ? tot / cnt : 0;

			(void) ustat_fprintf_unit(
			    fp, width, avg, &ustat_unit_time);
		}

		(void) fprintf(fp, "\n");
	}
}

/*
 * Print the ustat values in human-readable form.  To do this, we just slurp
 * out the values and then call ustat_ms_printv() on the resulting grid.
 */
void
ustat_ms_print(ustat_ms_t *ms, FILE *fp)
{
	ustat_named_t *cs = ms->usms_stats;
	const char *names, **namev;
	uint64_t *vbuf, *vp;
	ustat_ms_spec_t mss;

	mss.usms_rows = ustat_get_u8(ms, &ms->usms_nrows);
	mss.usms_cols = ustat_get_u8(ms, &ms->usms_ncols);
	mss.usms_ctons = ustat_get_u32(ms, &ms->usms_ctons);

	names = (char *)ustat_get_bytes(ms, &ms->usms_names);
	namev = alloca(sizeof (char *) * mss.usms_cols);
	mss.usms_names = namev;

	namev[0] = "COUNT";
	names += strlen(names) + 1;

	for (size_t c = 1; c < mss.usms_cols; c++) {
		namev[c] = names;
		names += strlen(names) + 1;
	}

	vbuf = alloca(sizeof (uint64_t) * mss.usms_rows * mss.usms_cols);
	vp = vbuf;

	for (size_t c = 0; c < mss.usms_rows * mss.usms_cols; c++)
		*vp++ = ustat_get_u64(ms, cs++);

	ustat_ms_printv(&mss, vbuf, fp);
}

void
ustat_ms_reset(ustat_ms_t *ms)
{
	const size_t rows = ustat_get_u8(ms, &ms->usms_nrows);
	const size_t cols = ustat_get_u8(ms, &ms->usms_ncols);

	for (size_t c = 0; c < rows * cols; c++)
		ustat_atomic_clr_u64(ms, &ms->usms_stats[c]);
}

/*
 * Deserialize the result of ustat_ms_export() into the caller's microstate
 * spec struct, and a pointer to the rows x cols grid of counter data.  The
 * caller must then (a) use the grid directly, or stuff it back into a ustat
 * using ustat_atomic_set_int(); and (b) call ustat_ms_destroy() on the 'msp'
 * spec.
 */
const uint64_t *
ustat_ms_import(ustat_ms_spec_t *msp, const void *buf, size_t len)
{
	const ustat_ms_plot_t *pp = buf;
	const char *names, **namev;
	size_t len1, len2;
	uint8_t rows, cols;

	len1 = sizeof (*pp);

	if (len < len1)
		return (ustat_null(NULL, EINVAL, "msacct too small: %zu", len));

	if (pp->usmp_mag1 != 'M' || pp->usmp_mag2 != 'S')
		return (ustat_null(NULL, EINVAL, "invalid msacct record"));

	rows = pp->usmp_rows;
	cols = pp->usmp_cols;
	len2 = len1 + sizeof (uint64_t) * (rows * cols - 1);

	if (len <= len2)
		return (ustat_null(NULL, EINVAL, "msacct too small: %zu", len));

	if ((namev = vmem_alloc(vmem_heap, sizeof (char *) * cols,
	    VM_NOSLEEP)) == NULL)
		return (ustat_null(NULL, ENOMEM, "failed to alloc buffer"));

	names = (char *)buf + len2;

	for (uint8_t c = 0; c < cols; c++) {
		namev[c] = names;
		names += strlen(names) + 1;
	}

	msp->usms_names = namev;
	msp->usms_rows = rows;
	msp->usms_cols = cols;
	msp->usms_ctons = pp->usmp_ctons;

	return (pp->usmp_stats);
}

/*
 * Serialize the microstate ustat to a buffer.  If buf is NULL and len is zero,
 * the size of the buffer needed to properly serialize is returned.
 */
size_t
ustat_ms_export(ustat_ms_t *ms, void *buf, size_t len)
{
	const size_t rows = ustat_get_u8(ms, &ms->usms_nrows);
	const size_t cols = ustat_get_u8(ms, &ms->usms_ncols);

	ustat_ms_plot_t *pp;
	uint64_t *vp;
	size_t rlen;

	rlen = sizeof (ustat_ms_plot_t) +
	    sizeof (uint64_t) * (rows * cols - 1) + ms->usms_names.usn_xlen;

	if (len == 0)
		return (rlen);

	pp = alloca(rlen);
	vp = pp->usmp_stats;

	pp->usmp_mag1 = 'M';
	pp->usmp_mag2 = 'S';
	pp->usmp_rows = rows;
	pp->usmp_cols = cols;
	pp->usmp_ctons = ustat_get_u32(ms, &ms->usms_ctons);

	for (size_t c = 0; c < rows * cols; c++)
		*vp++ = ustat_get_u64(ms, &ms->usms_stats[c]);

	bcopy(ustat_get_bytes(ms, &ms->usms_names),
	    vp, ms->usms_names.usn_xlen);

	bcopy(pp, buf, len < rlen ? len : rlen);
	return (rlen);
}

void
ustat_ms_destroy(ustat_ms_spec_t *msp)
{
	vmem_free(vmem_heap, (void *)msp->usms_names,
	    sizeof (char *) * msp->usms_cols);
	msp->usms_names = NULL;
}
