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

#ifndef _HRTIME_H
#define	_HRTIME_H

#include <stdint.h>
#include <time.h>

#ifdef	__cplusplus
extern "C" {
#endif

typedef enum hrclock {
	HRCLOCK_TSC,        /* x86 RDTSC or equivalent */
	HRCLOCK_MONOTONIC,  /* clock_gettime(CLOCK_MONOTONIC) */
} hrclock_t;

extern uint64_t gethrcycles(void);
extern uint64_t gethrtime(void);
extern uint32_t gethrfreq(void);  /* in KHz */
extern uint64_t hrcyctons(uint64_t cycles);
extern uint64_t hrcyctonsm(uint64_t cycles, uint64_t cycle_mult);
extern uint32_t gethrcycle_mult(void);
extern hrclock_t gethrclock(void);

#ifdef	__cplusplus
}
#endif

#endif	/* _HRTIME_H */
