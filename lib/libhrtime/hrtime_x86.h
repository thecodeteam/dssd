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

#ifndef HRTIME_X86_H
#define	HRTIME_X86_H

#include <stdint.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Definitions for the CPUID instruction.  These are summarized in:
 * Intel Processor ID and the CPUID Instruction, Application Note 485
 */
#define	CPUID_FCN_VID			0x00000000	/* CPUID 5.1.1 */
#define	CPUID_FCN_SFF			0x00000001	/* CPUID 5.1.2 */
#define	CPUID_FCN_MAX			0x80000000	/* CPUID 5.2.1 */
#define	CPUID_FCN_APM			0x80000007	/* CPUID 5.2.6 */

#define	CPUID_SIG_FAMILY(r)  \
    ((((r) >> 20) & 0xFF) + (((r) >> 8) & 0xF))		/* CPUID 5.1.2.2 E5-1 */

#define	CPUID_SIG_MODEL(r) \
    (((((r) >> 16) & 0xF) << 4) + (((r) >> 4) & 0xF))	/* CPUID 5.1.2.2 E5-2 */

#define	CPUID_SFF_EDX_TSC		(1 << 4)	/* CPUID 5.1.2 */
#define	CPUID_APM_EDX_TSC_INVARIANT	(1 << 8)	/* CPUID 5.2.6 */

#define	MSR_PLATFORM_INFO		0xCE		/* IA32_64 3B Tbl B-5 */
#define	MSR_PLATFORM_INFO_NTRATIO(m)	((uint8_t)(m >> 8)) /* IA32_64 3B B-5 */

/*
 * Encoding of pread() offsets for use with the cpuid(4) and msr(4) devices.
 * These devices use fake offsets as input arguments and return the registers.
 */
#define	CPUID_OFF(eax, ecx)	(((uint64_t)ecx << 32) | (uint64_t)eax)
#define	MSR_OFF(ecx)		((uint64_t)ecx)

typedef struct hrtime_regs {
	uint32_t r_eax;
	uint32_t r_ebx;
	uint32_t r_ecx;
	uint32_t r_edx;
} hrtime_regs_t;

#ifdef	__cplusplus
}
#endif

#endif	/* HRTIME_X86_H */
