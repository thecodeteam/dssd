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

#include <utrace_impl.h>

ut_buf_t *
utrace_buf_create(size_t size)
{
	ut_buf_t *bp = vmem_alloc(vmem_heap, sizeof (*bp), VM_SLEEP);

	bp->utbuf_base = vmem_alloc(vmem_heap, size, VM_SLEEP);
	bp->utbuf_bend = bp->utbuf_base + size;
	bp->utbuf_size = size;
	bp->utbuf_free = size;
	bp->utbuf_rptr = bp->utbuf_base;
	bp->utbuf_wptr = bp->utbuf_base;

	return (bp);
}

void
utrace_buf_destroy(ut_buf_t *bp)
{
	if (bp != NULL) {
		vmem_free(vmem_heap, bp->utbuf_base, bp->utbuf_size);
		vmem_free(vmem_heap, bp, sizeof (*bp));
	}
}

/*
 * Write a portion of the buffer by copying data from 'src' to utbuf_wptr,
 * wrapping the content around to the top of the buffer if necessary.
 * The content will be automatically cropped at utbuf_rptr, such that
 * we do not overwrite data that has yet to be consumed or erased.
 */
void
utrace_buf_write(ut_buf_t *bp, const void *src, size_t len)
{
	const uint8_t *src1, *src2;
	size_t len1, len2;

	if (len > bp->utbuf_size)
		len = bp->utbuf_size;

	src1 = src;
	len1 = len;

	if (len1 > (size_t)(bp->utbuf_bend - bp->utbuf_wptr))
		len1 = (size_t)(bp->utbuf_bend - bp->utbuf_wptr);

	if (len1 != 0)
		bcopy(src1, bp->utbuf_wptr, len1);

	src2 = src1 + len1;
	len2 = len - len1;

	if (len2 != 0)
		bcopy(src2, bp->utbuf_base, len2);

	if (len2 != 0)
		bp->utbuf_wptr = bp->utbuf_base + len2;
	else if (len1 != 0)
		bp->utbuf_wptr = bp->utbuf_wptr + len1;

	if (bp->utbuf_free != 0)
		bp->utbuf_free -= len;
}

/*
 * Erase a portion of the buffer (making more space free for writing) by
 * moving utbuf_rptr such that at least 'len' bytes are considered free.
 */
void
utrace_buf_erase(ut_buf_t *bp, size_t len)
{
	if (len > bp->utbuf_size - bp->utbuf_free)
		len = bp->utbuf_size - bp->utbuf_free;

	if (len > (size_t)(bp->utbuf_bend - bp->utbuf_rptr))
		bp->utbuf_rptr = bp->utbuf_base + len -
		    (size_t)(bp->utbuf_bend - bp->utbuf_rptr);
	else
		bp->utbuf_rptr = bp->utbuf_rptr + len;

	bp->utbuf_free += len;
}
