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
 * TODO: ARM provides a performance monitoring counter (PMCCNTR) which could be
 *       used by hrtime.  Unfortunately PMCCNTR is not available to user space
 *       by default (including the stock kernel used by our Armada CPU).  If
 *       hrtime performance on ARM becomes important in the future then we
 *       should implement a PMCCNTR option, e.g. enabled via the hrtime kmod.
 */

#include <stdint.h>

#include <hrtime.h>
#include <hrtime_impl.h>

static uint32_t hrtime_clock_mult;  /* used to convert clock cycles to ns */


inline uint32_t __attribute__ ((optimize("omit-frame-pointer")))
gethrcycle_mult(void)
{
        return (hrtime_clock_mult);
}

inline void __attribute__ ((optimize("omit-frame-pointer")))
sethrcycle_mult(uint32_t mult)
{
        hrtime_clock_mult = mult;
}

/*
 * The 32-bit version of hrcyctonsm() may overflow given that 128-bit math is
 * not available.  However, we don't support the TSC clock source in 32-bit mode
 * anyway, and the fallback is clock_gettime() which uses a 1ns timer,  i.e.
 * cycles == ns, so special-case this to stop potential overflows.
 */
inline uint64_t __attribute__ ((optimize("omit-frame-pointer")))
hrcyctonsm(uint64_t cycles, uint64_t clock_mult)
{
	if (clock_mult == (1ULL << CYC_TO_NS_SCALE))
		return (cycles);
	else
		return ((cycles * clock_mult) >> CYC_TO_NS_SCALE);
}

/*
 * hrcyctons() converts a cycle value (from gethrcycles()) to the number of
 * nanoseconds since an unspecified starting point.
 */
uint64_t __attribute__ ((optimize("omit-frame-pointer")))
hrcyctons(uint64_t cycles)
{
	return (hrcyctonsm(cycles, hrtime_clock_mult));
}

/*
 * ARM-specific hrtime init function.
 */
void
hrtime_init_cpu(void)
{
}
