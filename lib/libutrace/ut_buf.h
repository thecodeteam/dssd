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

#ifndef	_UT_BUF_H
#define	_UT_BUF_H

#ifdef	__cplusplus
extern "C" {
#endif

typedef struct ut_buf {
	uint8_t *utbuf_base;
	uint8_t *utbuf_bend;
	size_t utbuf_size;
	size_t utbuf_free;
	uint8_t *utbuf_rptr;
	uint8_t *utbuf_wptr;
} ut_buf_t;

extern ut_buf_t *utrace_buf_create(size_t);
extern void utrace_buf_destroy(ut_buf_t *);
extern void utrace_buf_write(ut_buf_t *, const void *, size_t);
extern void utrace_buf_erase(ut_buf_t *, size_t);

#ifdef	__cplusplus
}
#endif

#endif	/* _UT_BUF_H */
