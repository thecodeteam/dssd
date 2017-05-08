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

#ifndef _GETPCSTACK_H
#define	_GETPCSTACK_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <p2.h>

/*
 * Get up to pcstack_limit caller addresses, and store them in pcstack.  This
 * function returns the minimum of the computed depth and pcstack_limit.
 * In general, the following approaches to stack backtracing are possible:
 *
 * A. Use the compiler runtime.  GCC provides __builtin_return_address, but
 *    unfortunately this requires a depth parameter that is constant at compile
 *    time.  One could work around this by simply unrolling VMEM_TX_STACK
 *    worth of calls to it, and then only using pcstack_limit worth of them,
 *    but this approach also requires all the code on the stack to have been
 *    compiled with the same GCC options for it to work, which is unlikely.
 *
 * B. Use the debugger runtime.  Assuming everything has DWARF runtime data
 *    for handling functions compiled without frame pointers and the like, one
 *    can walk frame structures, and then as needed execute the DWARF state
 *    machine to compute the location of the frame and return address.  This is
 *    the approach used by glibc's backtrace(3) on x86_64.  Unfortunately, the
 *    glibc implementation makes use of calls to malloc to process DWARF.  This
 *    is an extremely bad design choice in general and fatal to use in libvmem.
 *
 * C. Use the ABI.  The Solaris implementation relies on the ABI requiring a
 *    a frame structure with specific stack alignment, and makes use of
 *    Solaris-specific routines to determine the current thread stack and
 *    signal stack boundaries to be sure to avoid dereferencing invalid memory.
 *
 * D. Compromise.  Since none of the above approaches work out well on Linux,
 *    a reasonable set of assumptions is that (1) libvmem itself is compiled
 *    with GCC so __builtin_frame_address(0) returns a correct starting point;
 *    (2) if anyone is using the optional VMEM_DEBUG debugging features, they
 *    must care about debugging, and if they care about debugging, they can be
 *    smart enough to compile with -fno-omit-frame-pointer; (3) we can
 *    compile libvmem itself with -fno-omit-frame-pointer to ensure that code
 *    locations that call getpcstack() have a frame pointer; and (4) most
 *    functions that call malloc or vmem_alloc() are not the sort that will
 *    benefit from omitting a frame pointer anyway, i.e. tiny leaf routines.
 *
 * Overall while distinctly unsatisfying option (D) is the present best choice.
 * The two most obvious improvements would be for Linux backtrace(3) to be
 * implemented without memory allocation, or for Linux to provide a vsyscall
 * akin to Solaris uucopy(2) to permit us to safely check for valid frames.
 */
static inline int
__attribute__((always_inline))
getpcstack(void **pcstack, int pcstack_limit, int zero)
{
	int depth = 0;
	void **f = __builtin_frame_address(0);

	for (void **lastf = f - 1;		// f[0]=next frame, f[1]=pc
	    IS_P2ALIGNED(f, sizeof (void *)) &&	// frame is pointer-aligned
	    f > lastf &&			// stack grows down
	    f < lastf + (1UL << 20) &&		// frame size < 1M* plausible
	    f[1] > (void *)4096 &&		// pc plausible -- not page 0
	    depth < pcstack_limit; lastf = f, f = f[0])
		pcstack[depth++] = f[1];

	for (int d = zero ? depth : pcstack_limit; d < pcstack_limit; d++)
		pcstack[d++] = NULL;

	return (depth);
}

#ifdef	__cplusplus
}
#endif

#endif	/* _GETPCSTACK_H */
