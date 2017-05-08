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

#include <alloca.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <math.h>

#include <bson.h>
#include <hrtime.h>
#include <ustat_hg.h>
#include <ustat_impl.h>

/* Converts a histogram bin value into a unit value */
typedef uint64_t (*ustat_hg_bin_cvt)(uint64_t bin_val, uint64_t uval);


static ustat_struct_t *
ustat_hg_ctor(ustat_handle_t *h, const char *ename, const char *gname,
    int statc, const ustat_struct_t *statv, void *uarg)
{
	ustat_type_t utype = (ustat_type_t)uarg;
	ustat_named_t *n;
	ustat_hg_t hg;
	size_t b, bins;
	char *s, *p;
	uint32_t ctons = gethrcycle_mult();
	uint64_t unused_val = 0;

	if (statc != 0) {
		return (ustat_null(h, EINVAL, "invalid statc for class_hg: "
		    "got %d, expected zero", statc));
	}

	if (statv != NULL) {
		return (ustat_null(h, EINVAL, "invalid statv for class_hg: "
		    "got %p, expected NULL", (void *)statv));
	}

	if (utype != USTAT_TYPE_DELTA && utype != USTAT_TYPE_SIZE &&
	    utype != USTAT_TYPE_UINT64)
		return (ustat_null(h, EINVAL,
		    "invalid ustat type for class_hg: %u", utype));

	hg.ushg_vtype.usn_name = "vtype";
	hg.ushg_vtype.usn_type = utype;
	hg.ushg_vtype.usn_xlen = 0;
	hg.ushg_vtype.usn_data = &unused_val;

	hg.ushg_ctons.usn_name = "ctons";
	hg.ushg_ctons.usn_type = USTAT_TYPE_UINT32;
	hg.ushg_ctons.usn_xlen = 0;
	hg.ushg_ctons.usn_data = &ctons;

	bins = sizeof (hg.ushg_bins) / sizeof (ustat_named_t);
	assert(bins < 100);   /* see below */
	s = alloca(bins * 4); /* size for "bNN\0" per bin */

	for (n = &hg.ushg_bins[0], p = s, b = 0; b < bins; b++, n++, p += 4) {
		(void) snprintf(p, 4, "b%zu", b);
		n->usn_name = p;
		n->usn_type = USTAT_TYPE_UINT64;
		n->usn_xlen = 0;
		n->usn_data = NULL;
	}

	return (ustat_insert(h, ename, gname,
	    &ustat_class_hg, sizeof (hg) / sizeof (ustat_named_t), &hg, uarg));
}

static int
ustat_hg_dtor(ustat_handle_t *h, void *carg)
{
	return (0);
}

static int
ustat_hg_export_bson(ustat_struct_t *s, int statc, bson_t *b, off_t d)
{
	ustat_hg_t *hg = s;
	size_t nbins = sizeof (hg->ushg_bins) / sizeof (ustat_named_t);
	ustat_type_t ut = hg->ushg_vtype.usn_type;
	ustat_hg_bin_cvt cvt = NULL;
	uint64_t uval = 0;
	char buf[32];
	uint64_t bin_val;
	int ret = 0;
	off_t o = d, vo, co;

	if (statc != 0 && statc != sizeof (ustat_hg_t) / sizeof (ustat_named_t))
		return (-1);

	if (ustat_add_bson_group(s, b, o, &o) != 0)
		return (-1);

	/* Add the value array */
	if (ut == USTAT_TYPE_DELTA) {
		/*
		 * Values are stored as cycles and must be converted to ns using
		 * the ctons ustat named.
		 */
		cvt = hrcyctonsm;
		uval = ustat_get_u32(hg, &hg->ushg_ctons);
	} else if (ut != USTAT_TYPE_SIZE && ut != USTAT_TYPE_UINT64)
		return (-1);

	if (ustat_set_bson_array(s, b, o, &vo, ustat_type2str(ut), "bins")
	    != 0)
		return (-1);

	for (uint32_t i = 0; i < nbins; i++) {
		if (i == 0)
			bin_val = 0;
		else {
			bin_val = 1ull << (i - 1);
			if (cvt != NULL)
				bin_val = cvt(bin_val, uval);
		}

		(void) snprintf(buf, sizeof (buf), "%d", i);
		ret |= bson_add_int64(b, vo, buf, bin_val);
	}

	/* Add the count array */
	if (ustat_set_bson_array(s, b, o, &co,
	    ustat_type2str(USTAT_TYPE_UINT64), "count") != 0)
		return (-1);

	for (uint32_t i = 0; i < nbins; i++) {
		(void) snprintf(buf, sizeof (buf), "%d", i);

		ret |= bson_add_int64(b, co, buf,
		    ustat_get_u64(hg, &hg->ushg_bins[i]));
	}

	return (ret);
}

const ustat_class_t ustat_class_hg = {
	.usc_name = "hg",
	.usc_ctor = ustat_hg_ctor,
	.usc_dtor = ustat_hg_dtor,
	.usc_bson = ustat_hg_export_bson,
};

/*
 * Convert a 64-bit integer to a bin from [0..64].  Bin 0 is reserved for 0,
 * all other bins represent the range [1<<b .. 1<<b+1), and the highest bin (64)
 * is also used for overflows (i.e. it represents all values >= 1<<63).  The
 * algorithm here can be summarized as follows:
 *
 * if x is 0, return bin 0
 * p = closest-power-of-two(x)
 * if p is 0 (overflow), return bin 64
 * if p != x (x is not a power-of-two), p >>= 1 (pick next lower power)
 * return bin ffs(p) (convert p to bit index)
 */
int
__attribute__ ((optimize("omit-frame-pointer")))
ustat_hg_bin64(uint64_t x)
{
	uint64_t p;

	if (x == 0)
		return (0);

	p = x - 1;

	p |= (p >> 1);
	p |= (p >> 2);
	p |= (p >> 4);
	p |= (p >> 8);
	p |= (p >> 16);
	p |= (p >> 32);

	p = p + 1;

	if (p == 0)
		return (64);

	if (p != x)
		p >>= 1;

	return (__builtin_ffsll(p));
}

void
ustat_hg_enter(ustat_hg_t *hg, uint64_t x)
{
	ustat_inc_u64(hg, &hg->ushg_bins[ustat_hg_bin64(x)]);
}

void
ustat_hg_atomic_enter(ustat_hg_t *hg, uint64_t x)
{
	ustat_atomic_inc_u64(hg, &hg->ushg_bins[ustat_hg_bin64(x)]);
}

/*
 * Convert the specified histogram snapshot into a plot data structure, which
 * tells the caller the minimum and maximum values, the range of non-zero bins,
 * and then produces a new set of bins sized for the given output width.
 */
void
ustat_hg_plot(ustat_hg_t *hg, ustat_hg_plot_t *hp, uint32_t width)
{
	size_t b, bins;
	uint64_t c;

	bins = sizeof (hg->ushg_bins) / sizeof (ustat_named_t);

	hp->ushp_lobin = -1u;
	hp->ushp_hibin = -1u;
	hp->ushp_min = UINT64_MAX;
	hp->ushp_max = 0;

	for (b = 0; b < bins; b++) {
		c = ustat_get_u64(hg, &hg->ushg_bins[b]);

		if (c < hp->ushp_min)
			hp->ushp_min = c;

		if (c > hp->ushp_max)
			hp->ushp_max = c;

		if (c != 0 && hp->ushp_lobin == -1u)
			hp->ushp_lobin = b;

		if (c != 0)
			hp->ushp_hibin = b;
	}

	/*
	 * Determine the range of bins to display.  If no bins had non-zero
	 * values, then arbitrarily tell the client to display three rows.
	 */
	if (hp->ushp_lobin == -1u && hp->ushp_hibin == -1u) {
		hp->ushp_lobin = 0;
		hp->ushp_hibin = 2;
	} else {
		if (hp->ushp_lobin == -1u)
			hp->ushp_lobin = 0;
		if (hp->ushp_hibin == -1u)
			hp->ushp_hibin = bins - 1;
	}

	hp->ushp_unit = (double)hp->ushp_max / width;

	for (b = 0; b < bins; b++) {
		hp->ushp_bins[b] = (uint32_t)lround(
		    ustat_get_u64(hg, &hg->ushg_bins[b]) / hp->ushp_unit);
	}
}

void
ustat_hg_reset(ustat_hg_t *hg)
{
	uint32_t b;

	for (b = 0; b < sizeof (hg->ushg_bins) / sizeof (ustat_named_t); b++)
		ustat_atomic_set_u64(hg, &hg->ushg_bins[b], 0);
}

/*
 * Prints a histogram to 'fp'.  If a bin-to-unit conversion function (cvt) is
 * specified, the bin values are converted using this function before being
 * passed off to the unit printer.
 */
static void
ustat_hg_fprintf_cvt(FILE *fp, const char *name, ustat_hg_t *hg,
    const ustat_unit_t *unit, ustat_hg_bin_cvt cvt, uint64_t uval)
{
	const char line[] = "------------------------------------------------";
	const char fill[] = "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@";
	const uint32_t llen = sizeof (line) - 1;
	const uint32_t nlen = strlen(name);
	ustat_hg_plot_t hp;
	uint32_t b, b2;

	(void) fprintf(fp, "%8s +- %s %*.*s+ %-20s\n",
	    "value", name, llen - 3 > nlen ? llen - 3 - nlen : 0,
	    llen - 3 > nlen ? llen - 3 - nlen : 0, line, "count");

	ustat_hg_plot(hg, &hp, llen);

	for (b = hp.ushp_lobin; b <= hp.ushp_hibin; b++) {
		if (b == 0)
			(void) fprintf(fp, "%8s", "0");
		else {
			b2 = 1ull << (b - 1);

			if (cvt != NULL)
				b2 = (cvt)(b2, uval);

			(void) ustat_fprintf_unit(fp, 8, b2, unit);
		}

		(void) fprintf(fp, " |%*.*s%*.*s| %-20ju\n",
		    hp.ushp_bins[b], hp.ushp_bins[b], fill,
		    llen - hp.ushp_bins[b], llen - hp.ushp_bins[b], "",
		    ustat_get_u64(hg, &hg->ushg_bins[b]));
	}

	(void) fprintf(fp, "%8s +%s+\n", "", line);
}

/*
 * Prints a histogram to 'fp'.  The histogram's bins are in 'unit' units.
 */
void
ustat_hg_fprint_unit(FILE *fp, const char *name, ustat_hg_t *hg,
    const ustat_unit_t *unit)
{
	ustat_hg_fprintf_cvt(fp, name, hg, unit, NULL, 0);
}

/*
 * Prints a histogram to 'fp'.  The histogram's bins are in cycles.  The bins
 * are printed as time values using the passed cycle-to-ns multiplier.
 */
void
ustat_hg_fprint_cyctotime(FILE *fp, const char *name, ustat_hg_t *hg,
    uint64_t cycle_mult)
{
	ustat_hg_fprintf_cvt(fp, name, hg, &ustat_unit_time,
	    hrcyctonsm, cycle_mult);
}


/*
 * Following are functions for stats that require multiple histogram plots.
 * Note: not meant to be used in fast-path.
 */

/* Bins per plot; affects histogram displays; max=65 */
#define HS_BINS_PER_PLOT (64)

void
ustat_hgm_enter(ustat_hg_multi_t *hm, uint64_t x)
{
	ustat_hg_t **hg = hm->ushm_hg;
	ustat_hg_plot_t *hp = hm->ushm_hp;
	uint32_t b, n;

	for (n = 0; x > hp->ushp_max && n < hm->ushm_plotc; n++)
		hp++;

	if (n == hm->ushm_plotc) {
		/* overflow, put into last bin */
		n--;
		b = HS_BINS_PER_PLOT - 1;
	} else if (x <= hp->ushp_min)
		b = hp->ushp_lobin;
	else
		b = (x - hp->ushp_min) / hp->ushp_unit;

	ustat_inc_u64(hg[n], &(hg[n]->ushg_bins[b]));
}

/*
 * Prints a histogram to 'fp'.  The histogram's bins are in 'unit' units.
 */
void
ustat_hgm_fprint_unit(FILE *fp, const char *hist_name, const char *bin_kind,
    const char *bin_count_type, ustat_hg_multi_t *hm)
{
	const char line[] = "------------------------------------------------";
	const char fill[] = "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@";
	const uint32_t llen = sizeof (line) - 1;
	const uint32_t nlen = strlen(hist_name);
	ustat_hg_plot_t *hp = hm->ushm_hp;
	ustat_hg_t **hg = hm->ushm_hg;
	uint32_t b, i, t;
	uint32_t udelta = hp->ushp_unit;
	uint32_t bdelta = hp->ushp_hibin + 1;
	uint32_t left_col_width = strlen(bin_kind) + 1;
	ustat_hg_plot_t *ref_hp;
	uint64_t c_max = 0;
	uint64_t hg_total = 0;
	double   c_unit;
	uint8_t udelta_log10;
	const int totalstrlen = 5;

	/* histogram header */
	(void) fprintf(fp, "%*s +%s+\n", left_col_width, "", line);
	(void) fprintf(fp, "%*s + %s %*.*s+\n", left_col_width,
	    "", hist_name, llen - 2 > nlen ? llen - 2 - nlen : 0,
	    llen - 2 > nlen ? llen - 2 - nlen : 0, "");
	(void) fprintf(fp, "%*s +%s+ %-20s\n", left_col_width,
	    bin_kind, line, bin_count_type);

	/* consolidate plots -- find max unit size */
	for (i = 0, ref_hp = hp; i < hm->ushm_plotc; i++, ref_hp++) {
		ustat_hg_plot(hg[i], ref_hp, llen);
		if (ref_hp->ushp_max > c_max)
			c_max = ref_hp->ushp_max;
		for (b = ref_hp->ushp_lobin; b <= ref_hp->ushp_hibin; b++) {
			hg_total += ustat_get_u64(hg[i], &(hg[i]->ushg_bins[b]))
			    * (hm->ushm_type == USHM_BIN_INDICIES ? 1 : b);
		}
	}

	/* check if there is nothing to plot */
	if (c_max == 0) {
		(void) fprintf(fp, "%*s +%s+\n", left_col_width, "", line);
		(void) fprintf(fp, "%*s %*s = %-20ju\n\n\n",
		    left_col_width + (int)strlen(line) - totalstrlen, hist_name,
		    totalstrlen, "Total", hg_total);
		return;
	}

	c_unit = (double)c_max / llen;
	/* consolidate plots -- refactor based on max unit size */
	for (i = 0, ref_hp = hp; i < hm->ushm_plotc; i++, ref_hp++) {
		for (b = ref_hp->ushp_lobin; b <= ref_hp->ushp_hibin; b++) {
			ref_hp->ushp_bins[b] = (uint32_t)lround(
			    ustat_get_u64(hg[i], &hg[i]->ushg_bins[b])
			    / c_unit);
		}
	}

	/* get log10(udelta) for plotting */
	udelta_log10 = 0;
	t = udelta;
	while (t) {
		udelta_log10++;
		t /= 10;
	}

	/* histogram plot */
	for (i = 0; i < hm->ushm_plotc; i++, hp++) {
		/* Skip if structure is empty */
		if (ustat_get_u64(hg[i],
		    &(hg[i]->ushg_bins[hp->ushp_lobin])) == 0)
			continue;

		for (b = hp->ushp_lobin; b <= hp->ushp_hibin; b++) {
			/* Skip empty bins */
			if (ustat_get_u64(hg[i],
			    &(hg[i]->ushg_bins[b])) == 0) {
				continue;
			}
			if (udelta == 1) {
				(void) fprintf(fp, "%*u", left_col_width,
				    (i * bdelta + b) * udelta);
			} else {
				(void) fprintf(fp, "%*u+%*d",
				    left_col_width - 2,
				    (i * bdelta + b) * udelta,
				    udelta_log10, udelta);
			}

			(void) fprintf(fp, " |%*.*s%*.*s| %-20ju\n",
			    hp->ushp_bins[b], hp->ushp_bins[b], fill,
			    llen - hp->ushp_bins[b],
			    llen - hp->ushp_bins[b], "",
			    ustat_get_u64(hg[i], &(hg[i]->ushg_bins[b])));
		}
	}
	(void) fprintf(fp, "%*s +%s+\n", left_col_width, "", line);
	(void) fprintf(fp, "%*s %*s = %-20ju\n\n\n",
	    left_col_width + (int)strlen(line) - totalstrlen, hist_name,
	    totalstrlen, "Total", hg_total);
}

void
ustat_hgm_create(ustat_handle_t *h, ustat_hg_multi_t *hm, uint32_t max,
    uint32_t unit, ustat_hg_multi_type_t type, const char *hg_name)
{
	ustat_hg_plot_t *hp;
	ustat_hg_t **hg;
	uint32_t num_plots = (max / unit + HS_BINS_PER_PLOT - 1) /
	    HS_BINS_PER_PLOT;
	uint32_t i;
	char name[9];
	uint8_t nlen;

	if (strlen(hg_name) < 5)
		nlen = strlen(hg_name);
	else
		nlen = 5;

	/* make sure names are unique; print fmt allocated 3 nibbles in name */
	if (num_plots > 0xFFF)
		num_plots = 0xFFF;

	hp = vmem_zalloc(vmem_heap,
	    sizeof (ustat_hg_plot_t) * num_plots, VM_SLEEP);
	hg = vmem_zalloc(vmem_heap,
	    sizeof (ustat_hg_t *) * num_plots, VM_SLEEP);

	snprintf(name, nlen + 1, hg_name);

	for (i = 0; i < num_plots; i++) {
		snprintf(name + nlen, 4, "%03X", i);
		hg[i] = ustat_insert(h, name, "hgtime", &ustat_class_hg, 0,
		    NULL, (void *)USTAT_TYPE_DELTA);
		hp[i].ushp_unit = unit;
		hp[i].ushp_min = i * HS_BINS_PER_PLOT * unit;
		hp[i].ushp_max =
		    (i + 1) * (unit * HS_BINS_PER_PLOT) - 1;
		hp[i].ushp_lobin = 0;
		hp[i].ushp_hibin = HS_BINS_PER_PLOT - 1;
	}

	hm->ushm_plotc = num_plots;
	hm->ushm_type = type;
	hm->ushm_hp = hp;
	hm->ushm_hg = hg;
}

void
ustat_hgm_destroy(ustat_hg_multi_t *hm)
{
	uint32_t i;

	vmem_free(vmem_heap, hm->ushm_hp,
	    sizeof (ustat_hg_plot_t) * hm->ushm_plotc);
	hm->ushm_hp = NULL;

	for (i = 0; i < hm->ushm_plotc; i++)
		ustat_delete(hm->ushm_hg[i]);
	vmem_free(vmem_heap, hm->ushm_hg,
	    sizeof (ustat_hg_t *) * hm->ushm_plotc);
	hm->ushm_hg = NULL;

	hm->ushm_plotc = 0;
}
