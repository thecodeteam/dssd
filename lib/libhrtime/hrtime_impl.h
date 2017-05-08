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

#ifndef HRTIME_IMPL_H
#define	HRTIME_IMPL_H

#include <stdint.h>

#ifdef	__cplusplus
extern "C" {
#endif

#define	ATTR_TSC		0x1	/* cpus have tsc instruction */
#define	ATTR_APM		0x2	/* cpus have advanced power mgmt */
#define	ATTR_TSC_INVARIANT	0x4	/* cpus have invariant tsc */
#define	ATTR_TSC_RATIO		0x8	/* cpus have invariant tsc ratio */
#define	ATTR_ALL		0xF	/* cpus have all required attrs */

#define NSEC_PER_MSEC (U_NANOSEC / U_MILLISEC)

/*
 * Used to convert a cycle value to a nanosecond value via a shift.  See tsc.c
 * ("Accelerators for sched_clock()") in the Linux kernel for a description of
 * why this value is appropriate.
 */
#define CYC_TO_NS_SCALE 10

typedef uint64_t (*gethrtime_funcp_t)(void);
typedef uint64_t (*gethrcycles_funcp_t)(void);

extern hrclock_t hrtime_clock;
extern uint32_t hrtime_cpu_attrs;
extern uint32_t hrtime_clock_khz;  /* clock rate in KHz */
extern gethrtime_funcp_t gethrtime_funcp;
extern gethrcycles_funcp_t gethrcycles_funcp;

extern void hrtime_init_cpu(void);
extern int __attribute__ ((format(printf, 2, 3)))
    hrtime_error(int err2, const char *format, ...);
extern void sethrcycle_mult(uint32_t mult);

#ifdef	__cplusplus
}
#endif

#endif	/* HRTIME_IMPL_H */
