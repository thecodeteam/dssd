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

#include <ucore_impl.h>

ssize_t
nt_fpregset_size(NElf_Word type, int fd, off_t off, pid_t tid)
{
	return (ucore_note_size(type,
	    "CORE", sizeof (elf_fpregset_t)));
}

ssize_t
nt_fpregset_dump(NElf_Word type, int fd, off_t off, pid_t tid)
{
	return (ucore_note_regs(type, fd, off,
	    tid, "CORE", sizeof (elf_fpregset_t)));
}
