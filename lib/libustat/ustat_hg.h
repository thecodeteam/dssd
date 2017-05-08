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

#ifndef _USTAT_HG_H
#define	_USTAT_HG_H

#include <ustat.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Userland Statistics Histogram Class
 *
 * This class provides the ability to quantize a set of input values such as
 * read or write sizes or offsets into power-of-two buckets and then display
 * these values as a histogram, similar to the effect of DTrace aggregations.
 */

/*
 * ushg_vtype, which is passed as the uarg to ustat_insert(), dicates how the
 * histogram row values should be printed.  For example:
 *
 *     USTAT_TYPE_DELTA: print as nanosecond values using ushg_ctons to convert
 *                       the raw cycle values in the bins to nanoseconds.
 *      USTAT_TYPE_SIZE: print using size units
 *    USTAT_TYPE_UINT64: print as a uint64.
 *
 *     All other types are invalid.
 */
typedef struct ustat_hg {
	ustat_named_t ushg_vtype;
	ustat_named_t ushg_ctons;
	ustat_named_t ushg_bins[65];
} ustat_hg_t;

typedef struct ustat_hg_plot {
	uint32_t ushp_bins[65];
	uint32_t ushp_lobin;
	uint32_t ushp_hibin;
	double ushp_unit;
	uint64_t ushp_min;
	uint64_t ushp_max;
} ustat_hg_plot_t;


typedef enum {
	USHM_BIN_INDICIES,
	USHM_BIN_COUNTS,
	USHM_MAX,
} ustat_hg_multi_type_t;

typedef struct ustat_hg_multi {
	ustat_hg_multi_type_t ushm_type;
	uint32_t ushm_plotc;
	ustat_hg_plot_t *ushm_hp;
	ustat_hg_t **ushm_hg;
} ustat_hg_multi_t;

extern const ustat_class_t ustat_class_hg;

extern int ustat_hg_bin64(uint64_t);
extern void ustat_hg_enter(ustat_hg_t *, uint64_t);
extern void ustat_hg_atomic_enter(ustat_hg_t *, uint64_t);
extern void ustat_hg_plot(ustat_hg_t *, ustat_hg_plot_t *, uint32_t);
extern void ustat_hg_reset(ustat_hg_t *);
extern void ustat_hg_fprint_unit(FILE *, const char *, ustat_hg_t *,
    const ustat_unit_t *);
extern void ustat_hg_fprint_cyctotime(FILE *, const char *, ustat_hg_t *,
    uint64_t);

extern void ustat_hgm_enter(ustat_hg_multi_t *, uint64_t);
extern void ustat_hgm_fprint_unit(FILE *, const char *, const char *,
    const char *, ustat_hg_multi_t *);
extern void ustat_hgm_create(ustat_handle_t *, ustat_hg_multi_t *, uint32_t,
    uint32_t, ustat_hg_multi_type_t, const char *);
extern void ustat_hgm_destroy(ustat_hg_multi_t *);

#ifdef	__cplusplus
}
#endif

#endif	/* _USTAT_HG_H */
