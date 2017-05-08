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

#ifndef	_UT_FILE_H
#define	_UT_FILE_H

#ifdef	__cplusplus
extern "C" {
#endif

typedef enum ut_file_sect {
	UT_FILE_SECT_HDR,
	UT_FILE_SECT_PROBE,
	UT_FILE_SECT_STR,
	UT_FILE_SECT_CODE,
	UT_FILE_SECT_MAX
} ut_file_sect_t;

typedef struct ut_file_subs {
	uint8_t *utfs_ptr;
	size_t utfs_len;
} ut_file_subs_t;

typedef struct ut_file {
	ut_file_subs_t utfi_sect[UT_FILE_SECT_MAX];
	uint8_t *utfi_data;
	size_t utfi_size;
} ut_file_t;

typedef struct ut_file_header {
	uint8_t utfh_ident[4];
	uint16_t utfh_wsize;
	uint16_t utfh_border;
	uint32_t utfh_proff;
	uint32_t utfh_prlen;
} ut_file_header_t;

#define	FHDR_IDENT_MAG0		0
#define	FHDR_IDENT_MAG1		1
#define	FHDR_IDENT_MAG2		2
#define	FHDR_IDENT_MAG3		3

#define	FHDR_IDMAG_MAG0		'\0'
#define	FHDR_IDMAG_MAG1		'U'
#define	FHDR_IDMAG_MAG2		'F'
#define	FHDR_IDMAG_MAG3		'O'

typedef struct ut_file_probe {
	uint32_t utfp_event;
	uint32_t utfp_file;
	uint32_t utfp_line;
	uint32_t utfp_code;
	uint32_t utfp_clen;
} ut_file_probe_t;

extern void utrace_file_alloc(ut_file_t *);
extern size_t utrace_file_write(ut_file_t *,
    ut_file_sect_t, const void *, size_t);
extern size_t utrace_file_wroff(const ut_file_t *, ut_file_sect_t);

#ifdef	__cplusplus
}
#endif

#endif	/* _UT_FILE_H */
