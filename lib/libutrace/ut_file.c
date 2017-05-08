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

static const size_t
utrace_file_align[UT_FILE_SECT_MAX] = {
	[UT_FILE_SECT_HDR] = sizeof (uint8_t),
	[UT_FILE_SECT_PROBE] = sizeof (uint32_t),
	[UT_FILE_SECT_CODE] = sizeof (uint64_t),
	[UT_FILE_SECT_STR] = sizeof (char),
};

/*
 * Calculate the final object file size, allocate a buffer for its content,
 * and then relocate the per-section pointers according to their sizes.
 * The start of each section is aligned according to utrace_file_align[] above.
 */
void
utrace_file_alloc(ut_file_t *file)
{
	ut_file_sect_t sect;
	size_t size = 0;

	for (sect = UT_FILE_SECT_HDR; sect < UT_FILE_SECT_MAX; sect++) {
		size = P2ROUNDUP(size, utrace_file_align[sect]);
		file->utfi_sect[sect].utfs_ptr = (uint8_t *)size;
		size += file->utfi_sect[sect].utfs_len;
		file->utfi_sect[sect].utfs_len = 0;
	}

	file->utfi_data = vmem_zalloc(vmem_heap, size, VM_SLEEP);
	file->utfi_size = size;

	for (sect = UT_FILE_SECT_HDR; sect < UT_FILE_SECT_MAX; sect++)
		file->utfi_sect[sect].utfs_ptr += (size_t)file->utfi_data;
}

/*
 * Write to the specified section.  If utrace_file_alloc() has been called,
 * copy in the data; otherwise just increase the size of the section.
 */
size_t
utrace_file_write(ut_file_t *file,
    ut_file_sect_t sect, const void *src, size_t len)
{
	ut_file_subs_t *sp = &file->utfi_sect[sect];
	size_t off = sp->utfs_ptr - file->utfi_data;

	if (sp->utfs_ptr != NULL) {
		bcopy(src, sp->utfs_ptr, len);
		sp->utfs_ptr += len;
	}

	sp->utfs_len += len;
	return (off);
}

size_t
utrace_file_wroff(const ut_file_t *file, ut_file_sect_t sect)
{
	return (file->utfi_sect[sect].utfs_ptr - file->utfi_data);
}
