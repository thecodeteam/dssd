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

#ifndef _USTAT_MS_H
#define	_USTAT_MS_H

#include <ustat.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Userland Statistics Microstate Class
 *
 * This class provides the ability to quantize operations that have microstate
 * accounting data into power-of-two buckets, and then display two-dimensional
 * analysis of their time distribution, and work distribution by microstate.
 * This is a more specialized form of the generic ustat_hg histogram.
 */

typedef struct ustat_ms {
	ustat_named_t usms_nrows;	/* number of rows / time buckets */
	ustat_named_t usms_ncols;	/* number of columns / microstates */
	ustat_named_t usms_names;	/* string array of microstate names */
	ustat_named_t usms_ctons;	/* cycle to ns for hrcyctonsm() */
	ustat_named_t usms_stats[1];	/* rows * cols encoded histogram */
} ustat_ms_t;

typedef struct ustat_ms_spec {
	const char *const *usms_names;	/* array of microstate names */
	uint8_t usms_rows;		/* number of rows / time buckets */
	uint8_t usms_cols;		/* number of cols / microstates */
	uint32_t usms_ctons;		/* cycles to nanoseconds */
} ustat_ms_spec_t;

extern const ustat_class_t ustat_class_ms;

extern void ustat_ms_enter(ustat_ms_t *, ustat_ms_spec_t *, const uint64_t *);
extern void ustat_ms_printx(ustat_ms_spec_t *, const uint64_t *, FILE *);
extern void ustat_ms_printv(ustat_ms_spec_t *, const uint64_t *, FILE *);
extern void ustat_ms_print(ustat_ms_t *, FILE *);
extern void ustat_ms_reset(ustat_ms_t *);

extern const uint64_t *ustat_ms_import(ustat_ms_spec_t *, const void *, size_t);
extern size_t ustat_ms_export(ustat_ms_t *, void *, size_t);
extern void ustat_ms_destroy(ustat_ms_spec_t *);

#ifdef	__cplusplus
}
#endif

#endif	/* _USTAT_MS_H */
