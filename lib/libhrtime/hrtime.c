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
 * hrtime
 *
 * 1. Introduction
 *
 * The need to measure CPU cycle counts to understand code duration or compare
 * performance has existed since, well, the first clock cycle executed.  And
 * modern CPUs have provided high-resolution cycle counters since around 1994.
 * However, in the sixteen years since, it still remains amazingly hard to get
 * a cheap monotonic nanosecond counter on modern CPUs and operating systems.
 * This situation occurred because while cycle counters were being introduced,
 * so too were varying CPU frequencies in SMP systems, varying CPU frequencies
 * dynamically to save power, dynamic hot-plug of CPUs, and virtualization.
 *
 * Solaris first introduced gethrtime() circa 1995 to read the SPARC %tick
 * register and report it as monotonically increasing number of nanoseconds.
 * Linux later provided the CLOCK_MONOTONIC clock for clock_gettime() that
 * has the identical semantics, and both OSes now use TSC on x86 underneath.
 * The Solaris version is optimized as a fast-trap, and the Linux version as a
 * VDSO that is executed directly from userland using a shared memory page.
 *
 * However, on x86 the implementation of these functions has remained somewhat
 * complicated because x86 CPUs have not, until very recently (Intel Nehalem),
 * provided a system-wide monotonically increasing timestamp register.  Early
 * implementations of TSC varied across x86 vendors, TSC increased at different
 * rates on different CPUs in the same box due to SKU frequency variation, and
 * the rate itself changed as CPUs changed P-, C-, or T-states.  As of 2010,
 * the situation improved when Intel added a CPUID capability to indicate that
 * TSC was invariant across state changes, and driven from a system-wide clock.
 *
 * But the OS implementations have not fully caught up to the benefits of the
 * new invariant TSC on x86, since they must cope with a variety of systems.
 *
 * The full history on the x86 TSC issues is most clearly described by:
 *
 * TSC and PM Events on AMD Processors, note by Rich Brunner on TSC history
 * http://lkml.org/lkml/2005/11/4/173
 *
 * TSC Mode on Xen 4.0, note by Dan Magenheimer on Xen TSC handling
 * http://lxr.xensource.com/lxr/source/docs/misc/tscmode.txt
 *
 * This library provides fully-optimized versions of gethrtime() and
 * gethrcycles() for Linux on x86-64 that derive the full performance benefit of
 * system-wide invariant TSC, and falls back to using CLOCK_MONOTONIC on systems
 * that don't have it.  A basic ARM port has also been provided, although it
 * currently only supports the CLOCK_MONOTONIC implementation.
 *
 * 2. Interfaces
 *
 * The interfaces exported by libhrtime are as follows:
 *
 * gethrcycles() - report the raw invariant cycle counter (64-bits)
 * gethrtime() - report the invariant nanosecond timer (64-bits)
 * gethrfreq() - report the invariant frequency in KHz (uint32_t)
 * hrcyctons() - convert cycles to ns since an unspecified starting point
 * hrcyctonsm() - convert cycles to ns using a specified clock multiplier
 * gethrcycle_mult() - report the cycle multiplier used to convert to ns
 * gethrclock() - report the clock being used by hrtime
 *
 * 3. Implementation
 *
 * The baseline assumptions for our faster implementation is that the Intel
 * TSC invariant flag means invariant across threads, cores, and sockets,
 * and does not cause TSC to stop or change rate across C-, -P, or T-states.
 * We then rely on the platform to arrange that TSCs are in sync (in Nehalem,
 * Intel provided this across all sockets that wired to the same IOH), or
 * that Linux will program TSCs to be in sync on dual or quad-IOH systems
 * or when a CPU is hot-plugged into a system (and thus might have TSC=0).
 *
 * We have found that the actual TSC tick rate does not correlate exactly with
 * the theoretical rate on modern (Nehalem / Sandy Bridge) systems.
 * Overclocking and spread spectrum both affect BCLK, as does the inherent
 * inaccuracy (e.g. +-100 ppm) of the source clock driving BCLK.
 *
 * Measuring the TSC rate to a high degree of accuracy is also problematic given
 * that we do not have access to a more accurate time source than the one being
 * measured.  NTP sounds enticing but in reality is susceptible to network
 * latency variation and takes ~48 hours to settle, thereby skewing any
 * short-duration time measurements performed at boot time by a user process.
 *
 * We have seen TSC inaccuracies of 5MHz on a 2GHz SB CPU.  For this reason, we
 * do not want to rely on the theoretical rate of the TSC.  KHz TSC resolution
 * is a reasonable goal in general, though, and can be grabbed from the Linux
 * kernel via a custom kernel module (a patch by a third party to expose tsc_khz
 * to userland via /sys was presented years ago but was rejected).
 *
 * The optimized 64-bit gethrtime() essentially just reads TSC and then adjusts
 * the resulting cycle count by the frequency to get nanoseconds.  If the TSC
 * is not invariant, or we cannot read the actual TSC rate from the kernel, we
 * fall back to the clock_gettime() method for both gethrcycles() and
 * gethrtime().  CLOCK_MONOTONIC is used in the latter case since
 * CLOCK_MONOTONIC_RAW is plain too slow (it doesn't use the VDSO).  As such,
 * the clock_gettime() fallback is affected by NTP adjustments.
 *
 * We use x86 CPUID to do the checks, which is described among other places by:
 * Intel Processor ID and the CPUID Instruction, Application Note 485.
 * The algorithm to determine if the system supports invariant TSC is:
 *
 * for each cpu
 *   supports CPUID instruction? (can check eflags, we just use cpuid(4))
 *   supports TSC instruction? (check CPUID feature flags, see 5.1.2.3)
 *   supports APM feature set? (check CPUID largest function, see 5.1.1)
 *   supports TSC invariant? (check APM feature mask, bit 8, see 5.2.6)
 *   reports TSC frequency? (check MSR_PLATFORM_INFO, see IA32_64 3B Tbl B-5)
 *
 * Unfortunately, the one remaining screw-up in the TSC interface is that
 * RDMSR remains privileged (and so does msr(7)), so while you can RDTSC and
 * read CPUID to find out that it's invariant, you can't get the frequency
 * without being the kernel or being root.  So alas we must also require
 * a custom udev(7) entry to add non-root access for msr(7) for this to work.
 * Maybe in the next millenium this will all be thought out coherently.
 *
 * 4. Performance
 *
 * Even when optimized as a Linux vdso, clock_gettime(CLOCK_MONOTONIC) has a
 * wad of overhead beyond just reading TSC, in that it must roughly do this:
 *
 * load and test gtod->sysctl_enabled for the timer lock
 * memory barrier
 * load and byte gtod->lock for the timer seqno
 * load gtod->wall_time_sec
 * load gtod->wall_time_nsec
 * load gtod->wall_to_monotonic.tv_sec
 * load gtod->wall_to_monotonic.tv_nsec
 * load and byte gtod->lock for the timer seqno
 * memory barrier
 * loop to normalize sec and nsec if needed
 * store sec to ts->tv_sec
 * store nsec to ts->tv_nsec
 *
 * and then the caller must:
 *
 * load sec
 * multiply by NANOSEC
 * load nsec
 * add them
 *
 * whereas when invariant TSC is present this all can be reduced to:
 *
 * memory barrier
 * rdtsc
 * multiply by frequency constant
 * divide by constant (via shifts)
 *
 * 128-bit math is required to convert from TSC-based cycles to nanoseconds,
 * since 64-bit math (using the fast algorithm above) would overflow in less
 * than a year of uptime on a modern system otherwise.  Two shifts are used
 * instead of an expensive 128-bit divide for speed (the frequency constant is
 * chosen so that the shifts are accurate at KHz resolution - see tsc.c in the
 * Linux kernel for more info).
 *
 * On a current 3GHz Nehalem CPU, executing tens of thousands of times with a
 * hot i-cache and d-cache, what we find is that our TSC-based gethrtime() costs
 * about 43 cycles, and our TSC-based gethrcycles() costs about 32 cycles, with
 * very small variations of 1 to 4 cycles.  Whereas the Linux VDSO for
 * clock_gettime(), which is libhrtime's fallback if the TSC rate cannot be
 * read from the kernel, costs about 128 cycles with huge variations of up to
 * 220 cycles when the system clock interrupt fires to update wall_time.
 *
 * In a storage system where we want to measure the latency of every request,
 * this effect is then magnified.  Using the TSC-based gethrcycles()/gethrtime()
 * results in +200K IOPS over calling clock_gettime() when using a single
 * request queue.
 */

#include <sys/types.h>
#include <sys/mman.h>
#include <sys/param.h>

#include <unistd.h>
#include <string.h>
#include <stddef.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <ctype.h>
#include <errno.h>

#include <hrtime.h>
#include <hrtime_impl.h>
#include <units.h>


hrclock_t hrtime_clock = HRCLOCK_MONOTONIC;
uint32_t hrtime_cpu_attrs = ATTR_ALL;
uint32_t hrtime_clock_khz = 0;  /* clock rate in KHz */
gethrtime_funcp_t gethrtime_funcp = NULL;
gethrcycles_funcp_t gethrcycles_funcp = NULL;

uint32_t
gethrfreq(void)
{
	return (hrtime_clock_khz);
}

/* clock_gettime() version of gethrcycles() / gethrtime(). */
static inline uint64_t __attribute__ ((optimize("omit-frame-pointer")))
gethrcycles_clock(void)
{
	struct timespec ts;

	(void) clock_gettime(CLOCK_MONOTONIC, &ts);
	return (ts.tv_sec * U_NANOSEC + ts.tv_nsec);
}

/* APIs that call the appropriate implementation. */
uint64_t __attribute__ ((optimize("omit-frame-pointer")))
gethrcycles(void)
{
	return ((*gethrcycles_funcp)());
}

uint64_t __attribute__ ((optimize("omit-frame-pointer")))
gethrtime(void)
{
	return ((*gethrtime_funcp)());
}

hrclock_t
gethrclock(void)
{
	return (hrtime_clock);
}

int __attribute__ ((format(printf, 2, 3)))
hrtime_error(int err2, const char *format, ...)
{
	int err1 = errno;
	va_list ap;

	if (getenv("HRTIME_DEBUG") != NULL) {
		(void) fprintf(stderr, "libhrtime[%d]: ", getpid());
		va_start(ap, format);
		(void) vfprintf(stderr, format, ap);
		va_end(ap);

		if (err1 != 0)
			(void) fprintf(stderr, ": %s\n", strerror(err1));
		else
			(void) fprintf(stderr, "\n");
	}

	if (err2 == ENOTRECOVERABLE)
		abort();

	errno = err2;
	return (-1);
}

static void __attribute__ ((constructor))
hrtime_init(void)
{
	char *e;
	uint32_t freq = 0;

	if ((e = getenv("HRTIME_ATTRS")) != NULL)
		hrtime_cpu_attrs = (int)strtol(e, NULL, 0);

	/*
	 * Init. the default hrtime implementation to clock_gettime().
	 * Port-specific code may override this.
	 */
	hrtime_clock = HRCLOCK_MONOTONIC;
	hrtime_clock_khz = U_NANOSEC / 1000;
	gethrtime_funcp = gethrcycles_clock;
	gethrcycles_funcp = gethrcycles_clock;

	/* Port-specific code which can override the defaults */
	hrtime_init_cpu();

	/* HRTIME_FREQ always overrides the default frequency */
	if ((e = getenv("HRTIME_FREQ")) != NULL) {
		(void) sscanf(e, "%u", &freq);

		if (freq != 0)
			hrtime_clock_khz = freq;
		else
			(void) hrtime_error(0, "invalid HRTIME_FREQ value");
	}

	sethrcycle_mult((NSEC_PER_MSEC << CYC_TO_NS_SCALE) / hrtime_clock_khz);

	if (getenv("HRTIME_DEBUG") != NULL) {
		(void) fprintf(stderr, "libhrtime[%d]: attr=%x freq=%uKHz\n",
		    getpid(), hrtime_cpu_attrs, hrtime_clock_khz);
	}
}
