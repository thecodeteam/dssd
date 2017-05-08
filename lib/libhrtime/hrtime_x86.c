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

#include <sys/types.h>
#include <sys/mman.h>
#include <sys/param.h>
#include <sys/syscall.h>

#include <unistd.h>
#include <string.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <ctype.h>
#include <errno.h>

#include <hrtime.h>
#include <hrtime_impl.h>
#include <hrtime_x86.h>

#include <sys/ioctl.h>
#include <emmintrin.h>
#include <x86intrin.h>


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

#if __WORDSIZE == 64

/*
 * hrcyctonsm() converts cycles to nanoseconds using the clock multiplier
 * passed.  This function is equivalent to:
 *
 *	return (cycles * clock_mult >> CYC_TO_NS_SCALE);
 *
 * but uses 128-bit intermediate values to stop overflows.
 */
inline uint64_t __attribute__ ((optimize("omit-frame-pointer")))
hrcyctonsm(uint64_t cycles, uint64_t clock_mult)
{
	uint64_t ns;

	asm volatile(
		"mulq	%2\n"
		"shrq	%3, %%rax\n"
		"shlq	%4, %%rdx\n"
		"orq	%%rdx, %%rax\n"
		: "=a" (ns)
		: "0" (cycles), "r" (clock_mult), "J" (CYC_TO_NS_SCALE),
		    "J" (64 - CYC_TO_NS_SCALE)
		: "rdx");

	return (ns);
}

#else

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

#endif  /* __WORDSIZE == 64 */

/*
 * hrcyctons() converts a cycle value (from gethrcycles()) to the number of
 * nanoseconds since an unspecified starting point.
 */
inline uint64_t __attribute__ ((optimize("omit-frame-pointer")))
hrcyctons(uint64_t cycles)
{
	return (hrcyctonsm(cycles, hrtime_clock_mult));
}

/* TSC version of gethrcycles(). */
static inline uint64_t __attribute__ ((optimize("omit-frame-pointer")))
gethrcycles_tsc(void)
{
	_mm_lfence();
	return (__rdtsc());
}

/* TSC version of gethrtime(). */
static uint64_t __attribute__ ((optimize("omit-frame-pointer")))
gethrtime_tsc(void)
{
	return (hrcyctons(gethrcycles_tsc()));
}

static int
hrtime_open_cpu(int cpuid, const char *kind)
{
	char *buf;
	size_t len;

	len = snprintf(NULL, 0, "/dev/cpu/%d/%s", cpuid, kind);
	buf = alloca(len + 1);
	(void) snprintf(buf, len + 1, "/dev/cpu/%d/%s", cpuid, kind);

	return (open(buf, O_RDONLY));
}

/*
 * Returns the specified CPU's theoretical frequency, based on its CPUID and MSR
 * values, or 0 on error.  Also determines whether the CPU lacks our required
 * capabilities and, if so, clears those bits in hrtime_cpu_attrs.
 */
static uint32_t
hrtime_get_cpuid_cpu_freq(int cpuid, int cpufd)
{
	hrtime_regs_t r;
	uint64_t m;
	int msrfd;
	ssize_t rv;
	double scale;
	char brand[16];
	uint32_t family, model, cpu_khz;

	if (pread(cpufd, &r, sizeof (r), CPUID_OFF(CPUID_FCN_VID, 0)) <= 0) {
		(void) hrtime_error(errno, "cpu[%d]: cpuid %x failed",
		    cpuid, CPUID_FCN_VID);
		return (0);
	}

	(void) snprintf(brand, sizeof (brand), "%.4s%.4s%.4s",
	    (char *)&r.r_ebx, (char *)&r.r_edx, (char *)&r.r_ecx);

	if (pread(cpufd, &r, sizeof (r), CPUID_OFF(CPUID_FCN_SFF, 0)) <= 0) {
		(void) hrtime_error(errno, "cpu[%d]: cpuid %x failed",
		    cpuid, CPUID_FCN_SFF);
		return (0);
	}

	if (!(r.r_edx & CPUID_SFF_EDX_TSC)) {
		hrtime_cpu_attrs &= ~ATTR_TSC;
		(void) hrtime_error(errno, "cpu[%d]: TSC not supported", cpuid);
		return (0);
	}

	family = CPUID_SIG_FAMILY(r.r_eax);
	model = CPUID_SIG_MODEL(r.r_eax);

	if (pread(cpufd, &r, sizeof (r), CPUID_OFF(CPUID_FCN_MAX, 0)) <= 0) {
		(void) hrtime_error(errno, "cpu[%d]: cpuid %x failed",
		    cpuid, CPUID_FCN_MAX);
		return (0);
	}

	if (r.r_eax < CPUID_FCN_APM) {
		hrtime_cpu_attrs &= ~ATTR_APM;
		(void) hrtime_error(errno, "cpu[%d]: APM not supported", cpuid);
		return (0);
	}

	if (pread(cpufd, &r, sizeof (r), CPUID_OFF(CPUID_FCN_APM, 0)) <= 0) {
		(void) hrtime_error(errno, "cpu[%d]: cpuid %x failed",
		    cpuid, CPUID_FCN_APM);
		return (0);
	}

	if (!(r.r_edx & CPUID_APM_EDX_TSC_INVARIANT)) {
		hrtime_cpu_attrs &= ~ATTR_TSC_INVARIANT;
		(void) hrtime_error(errno, "cpu[%d]: TSC not invariant", cpuid);
		return (0);
	}

	if ((msrfd = hrtime_open_cpu(cpuid, "msr")) == -1) {
		hrtime_cpu_attrs &= ~ATTR_TSC_RATIO;
		(void) hrtime_error(errno, "cpu[%d]: "
		    "failed to open MSR access device", cpuid);
		return (0);
	}

	rv = pread(msrfd, &m, sizeof (m), MSR_OFF(MSR_PLATFORM_INFO));
	(void) close(msrfd);

	if (rv != sizeof (m)) {
		hrtime_cpu_attrs &= ~ATTR_TSC_RATIO;
		(void) hrtime_error(errno, "cpu[%d]: "
		    "failed to read MSR %x", cpuid, MSR_PLATFORM_INFO);
		return (0);
	}

	/*
	 * The MSR NonTurbo ratio isn't a value: it's a scaled value.  And the
	 * scale is not in a register.  And they changed the scale.  So we have
	 * to hardwire detection of SandyBridge to determine the clock scale.
	 * A worldwide committee of bad software interface designers would have
	 * trouble equaling this much insanity to export one 5-digit number.
	 * In the latest Intel documentation,  Nehalem's clock scale is defined
	 * in IA32_64 3B B-83, and Sandy Bridge in IA32_64 3B B-136.
	 */
	if (strcmp(brand, "GenuineIntel") == 0 &&
	    family == 6 && (model == 0x2A || model == 0x2D))
		scale = 100.00;
	else
		scale = 133.33;

	cpu_khz = (uint32_t)(MSR_PLATFORM_INFO_NTRATIO(m) * scale * 1000);

	if (getenv("HRTIME_DEBUG") != NULL) {
		(void) fprintf(stderr, "libhrtime[%d]: cpu[%d]: "
		    "%s.%x.%x %.2f %uKHz\n", getpid(), cpuid,
		    brand, family, model, scale, cpu_khz);
	}

	return (cpu_khz);
}

/*
 * Private implementation of readdir that does not require malloc().  We need
 * this because hrtime_walk_cpus() has to get a list of cpu IDs, and the two
 * best ways to do that are (a) opendir("/dev/cpu") which calls malloc() from
 * glibc to create a DIR structure, or (b) sysconf(_SC_NPROCESSORS_*) which
 * calls malloc() to do fopen() or opendir() on /proc.  And since malloc()
 * might be umem_alloc(), and umem_alloc() calls gethrtime() ... kerblammo!
 *
 * To avoid this mess, our simple private version uses alloca() to make a
 * buffer on the stack of a single directory entry, and then we do getdents().
 * Since we don't need performance here, it suffices to reset the seek offset
 * every time to the exact boundary of the next entry and not bother buffering.
 * Also for simplicity we just return d_name which is all we need anyway.
 */
static char *
hrtime_readdir(int fd, char *buf, size_t len)
{
	/*
	 * This comes from include/linux/dirent.h:struct linux_dirent64
	 * but is not an exported interface.
	 */
	struct kdirent64 {
		uint64_t d_ino;
		uint64_t d_off;
		uint16_t d_reclen;
		uint8_t  d_type;  // getdents64() only: not in getdents()
		char d_name[0];
	} *dp;

	size_t dlen;
	int rlen;

	dlen = offsetof(struct kdirent64, d_name) + len + 2;
	dp = alloca(dlen);
	rlen = syscall(SYS_getdents64, fd, dp, dlen);

	if (rlen <= 0)
		return (NULL);

	(void) strncpy(buf, dp->d_name, len + 1);
	(void) lseek(fd, dp->d_off, SEEK_SET);

	return (buf);
}

/*
 * Returns the CPUs' theoretical frequency, based on their CPUID and MSR
 * values, or 0 on error.  Also determines whether any CPUs lack our required
 * capabilities and, if so, clears those bits in hrtime_cpu_attrs.
 */
static uint32_t
hrtime_get_cpuid_freq(void)
{
	uint32_t base_khz = 0, cur_khz = 0;
	int cpuid, cpufd, dirfd;
	char *dp, *ep;
	size_t ep_len;

	if ((dirfd = open("/dev/cpu", O_RDONLY)) == -1) {
		(void) hrtime_error(errno, "failed to open /dev/cpu");
		return (0);
	}

	ep_len = (size_t)fpathconf(dirfd, _PC_NAME_MAX);
	ep = alloca(ep_len + 1);

	while ((dp = hrtime_readdir(dirfd, ep, ep_len)) != NULL) {
		if (!isdigit(*dp))
			continue;

		cpuid = atoi(dp);
		cpufd = hrtime_open_cpu(cpuid, "cpuid");

		if (cpufd == -1 && errno != ENXIO) {
			base_khz = 0;
			(void) hrtime_error(errno,
			    "cpu[%d]: failed to open cpuid device", cpuid);
			break;
		} else if (cpufd < 0) {
			continue;
		}

		cur_khz = hrtime_get_cpuid_cpu_freq(cpuid, cpufd);
		(void) close(cpufd);

		/* Make sure every CPU's frequency is identical */
		if (cur_khz == 0 || (base_khz != 0 && cur_khz != base_khz)) {
			hrtime_cpu_attrs &= ~ATTR_TSC_RATIO;
			(void) hrtime_error(EINVAL,
			    "cpu[%d]: invalid tsc freq %uKHz, base freq %uKHz",
			    cpuid, cur_khz, base_khz);
			base_khz = 0;
			break;
		} else {
			base_khz = cur_khz;
		}
	}

	(void) close(dirfd);
	return (base_khz);
}

/*
 * x86-specific hrtime init function.  This implementation uses the TSC if
 * possible.  It first attempts to read the kernel-measured TSC.  If this fails,
 * it will attempt to read the theoretical CPU frequency from each CPU.
 * The user can override this behavior by setting the HRTIME_ATTRS environment
 * variable appropriately.
 */
void
hrtime_init_cpu(void)
{
	uint32_t tsc_khz = 0;

	if (hrtime_cpu_attrs == ATTR_ALL)
		tsc_khz = 0; /* not supported in this edition */

	if (tsc_khz == 0 && hrtime_cpu_attrs == ATTR_ALL)
		tsc_khz = hrtime_get_cpuid_freq();

	if (tsc_khz != 0) {
		hrtime_clock = HRCLOCK_TSC;
		hrtime_clock_khz = tsc_khz;
		gethrtime_funcp = gethrtime_tsc;
		gethrcycles_funcp = gethrcycles_tsc;
	} else
		(void) hrtime_error(0, "falling back to slow clock\n");
}
