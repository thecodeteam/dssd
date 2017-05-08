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
 * ustat import functions.
 *
 * These functions allow one to import / export ustats across systems,
 * e.g. 64-bit to 32-bit.
 */

#include <alloca.h>
#include <inttypes.h>
#include <string.h>

#include <ustat.h>
#include <ustat_hg.h>
#include <ustat_ms.h>
#include <ustat_impl.h>

/* Used for temporary space to import ustat entries */
typedef union ustat_imp_data {
	struct timespec uid_ts;
	struct timeval uid_tv;
	void *uid_p;
} ustat_imp_data_t;

/*
 * Relocate a pointer from a ustat_page64_t to a native pointer, verifying
 * that the pointer is valid.  Returns the relocated pointer, or NULL if the
 * pointer is invalid.
 */
static void *
ustat_relo_pg64_p(ustat_handle_t *h, const ustat_page64_t *pg64, uint64_t p)
{
	uint32_t plen = pg64->usp_size;
	uint64_t start_pg = pg64->usp_addr;
	uint64_t end_pg = (start_pg + plen - 1);

	if (p < start_pg || p > end_pg)
		return (ustat_null(h, -1, "pointer %jx outside %jx -> %jx",
		    p, start_pg, end_pg));

	return ((void *)(uintptr_t)(p - pg64->usp_addr + (uintptr_t)pg64));
}

/*
 * Convert a 64-bit ustat page string pointer to a native pointer.
 * The string is checked to make sure it is NULL terminated within the page.
 * Returns a native pointer to the string, or NULL if the pointer is invalid.
 */
static const char *
ustat_pg64_str(ustat_handle_t *h, const ustat_page64_t *pg64, uint64_t str64)
{
	uint32_t plen = pg64->usp_size;
	const char *end_p = (char *)pg64 + plen;
	const char *relo_str;

	relo_str = ustat_relo_pg64_p(h, pg64, str64);
	return (memchr(relo_str, '\0', end_p - relo_str) ? relo_str : NULL);
}

/*
 * Import a single ustat_named64_t into a local ustat_named_t.
 */
static int
ustat_import_named64(ustat_handle_t *h, const ustat_page64_t *pg64,
    ustat_named_t *dst, ustat_imp_data_t *dstd, ustat_named64_t *src)
{
	ustat_value64_t *datav = NULL;
	uint8_t *bufv = NULL;

	dst->usn_name = ustat_pg64_str(h, pg64, src->usn_name);
	dst->usn_type = src->usn_type;
	dst->usn_xlen = src->usn_xlen;

	if ((datav = ustat_relo_pg64_p(h, pg64, src->usn_data)) == NULL)
		return (ustat_error(h, -1, "invalid name data"));

	switch (src->usn_type) {
	case USTAT_TYPE_INT8:
	case USTAT_TYPE_INT16:
	case USTAT_TYPE_INT32:
	case USTAT_TYPE_INT64:
	case USTAT_TYPE_UINT8:
	case USTAT_TYPE_UINT16:
	case USTAT_TYPE_UINT32:
	case USTAT_TYPE_UINT64:
	case USTAT_TYPE_SIZE:
	case USTAT_TYPE_DELTA:
		dst->usn_data = datav;
		break;

	case USTAT_TYPE_CLOCK:
		dstd->uid_ts.tv_sec = datav->usv_u64 / U_NANOSEC;
		dstd->uid_ts.tv_nsec = datav->usv_u64 -
		    (dstd->uid_ts.tv_sec * U_NANOSEC);
		dst->usn_data = &dstd->uid_ts;
		break;

	case USTAT_TYPE_TOD:
		dstd->uid_tv.tv_sec = datav->usv_u64 / U_NANOSEC;
		dstd->uid_tv.tv_usec =
		    (datav->usv_u64 - (dstd->uid_tv.tv_sec * U_NANOSEC))
		    / (U_NANOSEC / U_MICROSEC);
		dst->usn_data = &dstd->uid_tv;
		break;

	case USTAT_TYPE_STRING:
	case USTAT_TYPE_BYTES:
	case USTAT_TYPE_ARRAY_U64:
		if ((bufv = ustat_relo_pg64_p(h, pg64, datav->usv_buf)) == NULL)
			return (ustat_error(h, -1, "invalid buffer"));
		dstd->uid_p = bufv;
		dst->usn_data = &dstd->uid_p;
		break;

	case USTAT_TYPE_UUID:
		if ((bufv = ustat_relo_pg64_p(h, pg64, datav->usv_buf)) == NULL)
			return (ustat_error(h, -1, "invalid uuid buf"));
		dst->usn_data = bufv;
		break;

	default:
		return (ustat_error(h, -1, "invalid type %u", src->usn_type));
	}

	return (0);
}

/*
 * Import a 64-bit ustat page.  The local system does not need to be 64-bit.
 * Returns a pointer to the imported page, or NULL if the src page is invalid.
 */
static ustat_struct_t *
ustat_import_page64(ustat_handle_t *h, const ustat_page64_t *pg64)
{
	uint64_t orig_pg = pg64->usp_addr;
	ustat_group64_t *g64 = NULL;
	ustat_named64_t *statv = NULL;
	ustat_struct_t *new_s = NULL;
	const char *fgname, *gname, *cname;
	ustat_named_t *tmp_statv = NULL;
	ustat_imp_data_t *tmp_data = NULL;
	uint16_t statc;
	unsigned elen;
	char *ename;
	const ustat_class_t *ustat_class;
	void *uarg = NULL;

	if ((g64 = ustat_relo_pg64_p(h, pg64, USTAT_PAGE64_TO_DATA(orig_pg)))
	    == NULL)
		return (ustat_null(h, -1, "invalid page"));

	if ((fgname = ustat_pg64_str(h, pg64, g64->usg_gname)) == NULL)
		return (ustat_null(h, -1, "invalid group name"));

	if ((cname = ustat_pg64_str(h, pg64, g64->usg_cname)) == NULL)
		return (ustat_null(h, -1, "invalid class name"));

	/* Split the {ename}.{gname} from the fqn into separate parts */
	if ((gname = strrchr(fgname, '.')) == NULL)
		return (ustat_null(h, -1, "invalid exe.group name"));

	gname++;
	elen = gname - fgname - 1;
	ename = alloca(elen + 1);
	strncpy(ename, fgname, elen);
	ename[elen] = '\0';
	statc = g64->usg_statc;
	ustat_class = ustat_cname_to_class(cname);

	/* Build temp ustat_named_t and pointer arrays, relocating ptrs */
	if (statc == 0)
		goto done_statv;

	/*
	 * allow import of ustats whose constructors are particular
	 * about parameters -- perhaps this should be moved to some
	 * per-class logic?
	 */
	if (ustat_class != &ustat_class_misc &&
	    ustat_class != &ustat_class_ms) {
		statc = 0;
		if (ustat_class == &ustat_class_hg) {
			if ((statv = ustat_relo_pg64_p(h,
			    pg64, g64->usg_statv)) == NULL)
				return (ustat_null(h, -1, "invalid statv"));

			uarg = (void *) statv[0].usn_type;
		}
		goto done_statv;
	}

	if ((statv = ustat_relo_pg64_p(h, pg64, g64->usg_statv)) == NULL)
		return (ustat_null(h, -1, "invalid statv"));

	tmp_statv = alloca(statc * sizeof (ustat_named_t));
	tmp_data = alloca(statc * sizeof (ustat_imp_data_t));

	for (uint16_t i = 0; i < statc; i++)
		if (ustat_import_named64(h, pg64, &tmp_statv[i], &tmp_data[i],
		    &statv[i]) != 0)
			return (NULL);
done_statv:

	/* Insert / update the ustat group */
	if ((new_s = ustat_lookup(h, ename, gname, NULL)) == NULL)
		new_s = ustat_insert(h, ename, gname,
		    ustat_class, statc, tmp_statv, uarg);
	else
		ustat_importv(new_s, statc, tmp_statv);

	return (new_s);
}

/*
 * Import a ustat buffer.
 *
 * Returns 0 on success, or -1 if the buffer is invalid.
 */
int
ustat_import_mbuf(ustat_handle_t *h, const ustat_mbuf_t *m)
{
	const ustat_page_t *mp = m->usm_data;
	uint8_t mag3 = mp->usp_magic[3];

#if __BYTE_ORDER == __LITTLE_ENDIAN
	if ((mag3 & USTAT_MAG3_LE) == 0)
#else
	if ((mag3 & USTAT_MAG3_BE) == 0)
#endif
		return (ustat_error(h, -1, "invalid page endianness"));

	if ((mag3 & USTAT_MAG3_64) != 0)
		return (ustat_import_page64(h, (ustat_page64_t *)mp) == NULL
		    ? -1 : 0);
	else
		return (ustat_error(h, -1, "unsupported 32-bit page import"));

	return (-1);
}
