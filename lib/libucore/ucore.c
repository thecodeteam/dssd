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

/**
 * @fi ucore.c
 * @br Userland Core Dump Library @bc
 *
 * 1. Introduction
 *
 * For as long as debugging has existed, the memory dump has been a primary tool
 * for programmers to analyze complex, fatal execution failure in production.
 *
 * Stanley Gill, writing in late 1950 in his seminal "Diagnosis of Mistakes in
 * Programmes on the EDSAC" (Proc. Royal Society, Vol 206, No 1087), put it so:
 *
 * "One way of obtaining such a [debugging] record is to insert into the
 * machine, after the operation of the original programme has stopped, a second
 * programme causing the teleprinter to print the contents of relevant parts of
 * the store.  This method has come to be known as the post-mortem technique."
 *
 * And thus, 61 years later, libucore.  But of course UNIX itself provides
 * kernel-driven core dumps for all processes, so why redo this in userland?
 * Fundamentally, kernel core dumping still suffers from these deficiencies:
 *
 * - The kernel only filters mappings based on their attributes (e.g. include
 *   or omit MAP_SHARED), but neither Solaris nor Linux offer a way to filter
 *   mappings based on their semantic meaning in the program.  For Flood, we
 *   want to omit certain large buffers (like the 4G+ DMA arena) whose content
 *   is not typically required, may contain secure data, and wastes time+space.
 *
 * - The kernel omits critical process state from the core dump.  In Solaris,
 *   this got better over time but (for example) fd state is still missing.
 *   In Linux, the situation is more egregious-- the bulk of the proc(5) state
 *   other than registers is simply not stored in a core file at all.
 *
 * - The kernel cannot include device state external to the process in a core
 *   dump, because this is generally unsafe, so device mappings are omitted.
 *   But for a userland i/o stack such as Flood, it is critical that we be able
 *   to write safe routines to capture read-only device registers with MMIOs
 *   in order to capture the device state along with the state of our software.
 *
 * - The kernel core dump code in both Linux and Solaris is not optimized for
 *   performance, and thus the speed of a multi-gigabyte core dump is awful,
 *   and typically causes the VM system and page cache to grind to a halt. (And
 *   Solaris solved the page cache issue by slowing i/o even more with delays.)
 *   It is much simpler and safer to address these design flaws in userland,
 *   where it is far easier to develop and debug a parallel i/o implementation.
 *
 * - The kernel typically provides no status as to core dumping: no progress
 *   indicators, and no summary of the failure.  And since core dumps of huge
 *   processes are slow, you might waste minutes wondering if the program is
 *   hung or watching the core file write, without having any data yet.
 *
 * - The kernel does not consistently implement interruptible i/o for cores,
 *   since the core i/o path may not enable signals.  (e.g. on Linux, ELF core
 *   dumps over NFS are not interruptible using SIGINT, wasting yet more of
 *   your developer time when you see a particular assertion fire yet again.)
 *
 * 2. Feature Set
 *
 * Libucore provides solutions to these problems, for large complex processes
 * such as flood.  It provides the following basic feature set:
 *
 * - application-aware filtering: ucore_include()/exclude() API for mappings
 * - enhanced core notes: key proc(5) files are stored as string sections
 * - enhanced state save: pid, tid, pthread_t, errno, stack are saved by ucore
 * - zero-copy architecture: mappings page-flip directly to the filesystem
 * - banner and progress: for the tty, signal and stack, and a progress meter
 * - interruptible: using SIGINT, core dump can be interrupted, with feedback
 * - ulimit override: user core dump writes until error, regardless of ulimit
 * - options to configure user core dump, kernel core dump, or both
 * - options to configure core dump path, or inherit the kernel's core pattern
 *
 * Future work that can be easily built on this infrastructure includes:
 *
 * - symbol tables for every load object saved in the core
 * - gcore(1) api for generating a live core without exiting
 * - application callbacks for device register save
 * - on-the-fly compression with zlib during output
 * - more proc(5) notes including per-fd path and status
 *
 * 3. Design and Implementation
 *
 * The userland core dump design and basic control flow is as follows:
 *
 * - at process startup, libucore's .init section forks a child process
 * - the parent process is connected to the child using a pipe
 * - the parent intercepts all fatal signals, and directs them to libucore
 * - on a fatal signal, we gather debug state, stop all threads, and then
 *   walk our own address space using proc(5) to get a list of mappings
 * - for each mapping, we then send a Phdr over the pipe to the child
 * - for each mapping, we then vmsplice() its pages to the child, who then
 *   splice()s from the pipe directly to the core file at the proper offset
 * - the child also reads all the parent's proc and register state, and
 *   handles all of the ELF Ehdr, Phdr, and Shdr construction
 * - the child exits, and the parent jumps back to the original failure so as
 *   to let the kernel have a turn at its core dump, and to set exit status
 *
 * The important constraints on the implementation are:
 *
 * - libucore sets up an alternate signal stack for handling fatal signals,
 *   and essentially does as little as possible, using primarily system calls,
 *   after a fault.  All the complex code is running in the child process.
 *
 * - If anything goes wrong, or if the user requests a kernel dump, we return
 *   back to the original fault and let the kernel try to dump a core.
 *
 * - Linux kernel files necessary for the core files notes cannot be compiled
 *   in userland in code that also includes normal userland header files.  As
 *   such, the ELF notes are isolated into separate source files, with the
 *   special ucore_impl.h header providing a bridge between this code and
 *   a set of common mechanisms implemented here in the common libucore.
 *
 * 4. Configuration Options
 *
 * libucore can be controlled using these environment variables:
 *
 * UCORE_PATH: if set, this path will be used for the core file.  Otherwise
 *   libucore will try the OS setting from /proc/sys/kernel/core_pattern,
 *   or a hard-wired default of core.%p.  All paths can use any of the tokens
 *   described in core(5), or the libucore token %T for and ISO 8601 timestamp.
 *
 * UCORE_OPTIONS: if set, this comma-separated list of options controls ucore's
 *   behavior.  The option tokens that can be specified are as follows:
 *
 *   user - generate a core file in user mode using libucore (default)
 *   nouser - do not generate a core file in user mode
 *   kernel - generate a core file in kernel mode
 *   nokernel - do not generate a core file in kernel mode (default)
 *   banner - print the signal, stack, and progress to stderr (default)
 *   nobanner - do not print the banner and progress meter
 *   exclude - permit application exclusions using ucore_exclude() (default)
 *   noexclude - disable application exclusions and dump everything
 *
 * libcore is enabled for any program that links to it, but clients can also
 * use the APIs to configure libucore behaviors:
 *
 * ucore_exclude(void *base, size_t size) - exclude the specified mapping
 *   from the userland core dump.  (by default, all mappings are included)
 *
 * ucore_include(void *base, size_t size) - include the specified mapping
 *   in the userland core dump, undoing the effect of a previous ucore_exclude.
 *
 * 5. Post-Mortem Debugging Tips
 *
 * - Linux proc(5) files are stored in the core file as string sections.
 *   These can be displayed using readelf(1).  For example:
 *
 *   $ readelf -p environ core.12345
 *
 *   will display /proc/<pid>/environ at the time of the core dump.
 *
 * - libucore captures all of the critical process state such as thread, TID,
 *   PID, errno, signal, stack etc. in a static structure named 'ucore'.
 *   Therefore most post-mortem analysis can begin with "print ucore" in gdb(1)
 *   to get a summary of all the critical state at the time of the failure.
 *
 * @ec
 */

#include <sys/types.h>
#include <sys/mman.h>
#include <sys/uio.h>
#include <sys/syscall.h>
#include <sys/utsname.h>
#include <sys/eventfd.h>
#include <sys/wait.h>
#include <sys/resource.h>
#include <sys/time.h>

#include <linux/ptrace.h>

#include <pthread.h>
#include <ucontext.h>
#include <unistd.h>
#include <signal.h>
#include <endian.h>
#include <search.h>
#include <strings.h>
#include <string.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
#include <dirent.h>
#include <fcntl.h>
#include <errno.h>
#include <elf.h>
#include <inttypes.h>

#include <p2.h>
#include <list.h>
#include <units.h>
#include <nelf.h>
#include <hrtime.h>
#include <vmem.h>
#include <utrace.h>
#include <ucore.h>

#include <ucore_impl.h>

#if defined(__x86_64__)
#define	UCORE_MC_REG_PC(mc) ((mc)->gregs[REG_RIP])
#define	UCORE_MC_REG_FP(mc) ((mc)->gregs[REG_RBP])
#elif defined(__i386)
#define	UCORE_MC_REG_PC(mc) ((mc)->gregs[REG_EIP])
#define	UCORE_MC_REG_FP(mc) ((mc)->gregs[REG_EBP])
#elif defined(__arm__)
#define	UCORE_MC_REG_PC(mc) ((mc)->arm_pc)
#define	UCORE_MC_REG_FP(mc) ((mc)->arm_fp)
#else
#error "unknown arch"
#endif

/*
 * Some platforms (SLES11SP3 for one) support these interfaces but their
 * headers lag their kernels.
 */
#ifdef NEED_PTRACE_REGSET
#define	PTRACE_GETREGSET	0x4204
#define	PTRACE_SETREGSET	0x4205
#define	PN_XNUM			0xffff  /* e_phnum overflowed */
#define	NT_X86_XSTATE		0x202	/* Elf note for x86 extended state */
#endif

struct frame {
	greg_t fr_savfp;
	greg_t fr_savpc;
};

typedef struct ucore_func {
	void (*c_func)(void *);	/* callback */
	void *c_farg;		/* argument */
	list_node_t c_list;	/* linkage */
} ucore_func_t;

static struct ucore {
	pid_t c_pid;		/* getpid() */
	pid_t c_tid;		/* gettid() */
	pthread_t c_thr;	/* pthread_self() */
	uint64_t c_cyc;		/* gethrcycles() */
	uint64_t c_hrt;		/* gethrtime() */
	struct timespec c_tod;	/* clock_gettime(CLOCK_REALTIME) */
	struct timespec c_sys;	/* clock_gettime(CLOCK_MONOTONIC) */
	int c_errno;		/* libc errno */
	uid_t c_uid;		/* getuid() */
	gid_t c_gid;		/* getgid() */
	struct rlimit c_lim;	/* getrlimit(RLIMIT_CORE) */
	struct utsname c_uts;	/* uname() for this system */
	siginfo_t c_sig;	/* signal that caused core */
	ucontext_t c_ctx;	/* saved user context */
	uintptr_t c_stk[16];	/* initial stack trace */
	int c_stkdepth;		/* initial stack depth */
} ucore;

extern const char *const sys_sigabbrev[]; /* libc.so's signal abbreviations */
extern const char *const *_dl_argv; /* ld.so's argv[] */

size_t ucore_pgsize = 0;	/* _SC_PAGESIZE */
long ucore_clktck = 0;		/* _SC_CLK_TCK */

/*
 * Table of functions corresponding to PT_NOTE entries to generate.  In theory,
 * order does not matter, but it is best to keep this in sync with the kernel,
 * as various core file consumers may accidentally encode the ordering.
 */
static const ucore_note_t ucore_notes[] = {
	{ NT_PRSTATUS, nt_prstatus_size, nt_prstatus_dump },
	{ NT_PRPSINFO, nt_prpsinfo_size, nt_prpsinfo_dump },
	{ NT_AUXV, nt_auxv_size, nt_auxv_dump },
	{ NT_FPREGSET, nt_fpregset_size, nt_fpregset_dump },
#if defined(__i386)
	{ NT_PRXFPREG, nt_prxfpreg_size, nt_prxfpreg_dump },
#endif
#if defined(__x86_64__) || defined(__i386)
	{ NT_X86_XSTATE, nt_xstate_size, nt_xstate_dump },
#endif
	{ 0, NULL, NULL }
};

/*
 * Table of proc(5) files to embed into the core file as non-loadable sections
 * that can be examined for debugging using readelf -p <name> <core>
 *
 * "numa_maps" should be included, but reading it causes kernel oopses.
 */
static const char *const ucore_procs[] = {
	"cmdline", "environ", "limits", "maps", "smaps", "status"
};

#define	ucore_nprocs	(sizeof (ucore_procs) / sizeof (ucore_procs[0]))

#define	UCORE_R		0	/* ucore_pipe[] read-side */
#define	UCORE_W		1	/* ucore_pipe[] write-side */

#define	UCORE_F_KERNEL	0x01	/* kernel core dump */
#define	UCORE_F_USER	0x02	/* user core dump */
#define	UCORE_F_BANNER	0x04	/* print banner */
#define	UCORE_F_EXCLUDE	0x08	/* enable exclusions */
#define	UCORE_F_ENABLE	0x10	/* enable/disable override */
#define	UCORE_F_NO(x)	((x) << 8)	/* explicit disable */

bool __attribute__((weak)) ucore_enable = false;
static utrace_handle_t *ucore_utrace = NULL;
static DIR *ucore_threads = NULL;
static int ucore_sig = 0;
static char ucore_vbuf[256];
static const size_t ucore_vlen = sizeof (ucore_vbuf);
static char ucore_pbuf[4096];
static const size_t ucore_plen = sizeof (ucore_pbuf);
static pid_t ucore_child = -1;
static int ucore_pipe[2] = { -1, -1 };
static stack_t ucore_stack = { MAP_FAILED, 0, 0 };
static char ucore_upath[PATH_MAX];
static char ucore_kpath[PATH_MAX];
static char ucore_epath[PATH_MAX];
static int ucore_flags = UCORE_F_USER | UCORE_F_EXCLUDE;
static size_t ucore_throttle = 64 * U_MB;
static volatile int ucore_intr = 0;
static sigset_t ucore_mask;

static pthread_mutex_t ucore_excl_mutex = PTHREAD_MUTEX_INITIALIZER;
static NElf_Phdr *ucore_excl_phdrs = NULL;
static size_t ucore_excl_valid = 0;
static size_t ucore_excl_count = 0;

static pthread_mutex_t ucore_func_mutex = PTHREAD_MUTEX_INITIALIZER;
static list_t ucore_func_list;

static int __attribute__ ((const))
ucore_addr_compare(const NElf_Addr l, const NElf_Addr r)
{
	if (l < r)
		return (-1);

	if (l > r)
		return (+1);

	return (0);
}

static int
ucore_excl_compare(const NElf_Phdr *l, const NElf_Phdr *r)
{
	if (l->p_vaddr != r->p_vaddr)
		return (ucore_addr_compare(l->p_vaddr, r->p_vaddr));

	if (l->p_memsz != r->p_memsz)
		return (ucore_addr_compare(l->p_memsz, r->p_memsz));

	return (0);
}

static int
utrace_excl_contain(const NElf_Phdr *k, const NElf_Phdr *p)
{
	if (k->p_vaddr - p->p_vaddr < p->p_memsz)
		return (0); /* key in range [p_vaddr, p_vaddr + p_memsz) */

	return (ucore_addr_compare(k->p_vaddr, p->p_vaddr));
}

static int
ucore_excl_mapping(const NElf_Phdr *p)
{
	const NElf_Phdr *e;

	if (!(ucore_flags & UCORE_F_EXCLUDE))
		return (0); /* exclusions are disabled at user request */

	if (pthread_mutex_trylock(&ucore_excl_mutex) != 0)
		return (0); /* if we're in a bad state, assume inclusion */

	e = bsearch(p, ucore_excl_phdrs, ucore_excl_valid,
	    sizeof (NElf_Phdr), (__compar_fn_t)utrace_excl_contain);

	(void) pthread_mutex_unlock(&ucore_excl_mutex);
	return (e != NULL);
}

pid_t
ucore_getpid(void)
{
	return (ucore.c_pid);
}

pid_t
ucore_gettid(void)
{
	return (ucore.c_tid);
}

/*
 * Copy the representative thread's saved registers from the time of the fatal
 * signal into the outbound ELF register set, so that the core file reflects
 * this thread context rather than when ptrace() attaches to us in libucore.
 *
 * Unfortunately, Linux has made a complete mess of their register types due to
 * so many competing interfaces defining their own in parallel.  To summarize:
 *
 * The linux/elfcore.h interface defines prstatus.pr_reg as type elf_gregset_t
 * elf_gregset_t is an array of longs of size equal to struct user_regs_struct
 * struct user_regs_struct is a superset of ptrace's struct pt_regs
 * ptrace's pt_regs is the way registers push on the stack upon syscall entry
 *
 * Meantime, Linux signal handling uses its own arch-specific struct sigcontext
 *   to store registers to the stack when SA_SIGINFO is set, but struct
 *   sigcontext duplicates the register set in an entirely different order.
 *
 * And then glibc consumes the kernel's sigcontext, but rewrites it as follows:
 *
 * ucontext_t.uc_mcontext.gregs is of type gregset_t, provided by glibc
 * gregset_t is an array of longs of size declared by a static #define
 * ucontext.h has #defines and enums for indexing gregset_t
 *
 * When the kernel dumps core, it copies a pt_regs to elf_gregset_t, relying on
 * the fact that pt_regs is defined as a proper subset of user_regs_struct.
 *
 * Can't be made any simpler than that, right?
 *
 * But for libucore, we start with the result of SA_SIGINFO, so we need to go
 * backwards from ucontext_t's gregset_t to the elf_gregset_t, shown below.
 * To make this code simpler, our <ucore_impl.h> typedef's elf_gregset_t to be
 * user_regs_struct instead of its array form so we don't need more #defines.
 */
void
ucore_getreg(struct user_regs_struct *dst)
{
	const mcontext_t *src = &ucore.c_ctx.uc_mcontext;

#if defined(__x86_64__)
	union {
		greg_t csgsfsreg;
		struct {
			uint16_t cs;
			uint16_t gs;
			uint16_t fs;
			uint16_t __pad0;
		} csgsfs;
	} u;
	dst->r15 = src->gregs[REG_R15];
	dst->r14 = src->gregs[REG_R14];
	dst->r13 = src->gregs[REG_R13];
	dst->r12 = src->gregs[REG_R12];
	dst->rbp = src->gregs[REG_RBP];
	dst->rbx = src->gregs[REG_RBX];
	dst->r11 = src->gregs[REG_R11];
	dst->r10 = src->gregs[REG_R10];
	dst->r9 = src->gregs[REG_R9];
	dst->r8 = src->gregs[REG_R8];
	dst->rax = src->gregs[REG_RAX];
	dst->rcx = src->gregs[REG_RCX];
	dst->rdx = src->gregs[REG_RDX];
	dst->rsi = src->gregs[REG_RSI];
	dst->rdi = src->gregs[REG_RDI];
	dst->rip = src->gregs[REG_RIP];
	u.csgsfsreg = src->gregs[REG_CSGSFS];
	dst->cs = u.csgsfs.cs;
	dst->eflags = src->gregs[REG_EFL];
	dst->rsp = src->gregs[REG_RSP];
	dst->fs = u.csgsfs.fs;
	dst->gs = u.csgsfs.gs;
#elif defined(__i386)
	dst->ebx = src->gregs[REG_EBX];
	dst->ecx = src->gregs[REG_ECX];
	dst->edx = src->gregs[REG_EDX];
	dst->esi = src->gregs[REG_ESI];
	dst->edi = src->gregs[REG_EDI];
	dst->ebp = src->gregs[REG_EBP];
	dst->eax = src->gregs[REG_EAX];
	dst->xds = src->gregs[REG_DS];
	dst->xes = src->gregs[REG_ES];
	dst->xfs = src->gregs[REG_FS];
	dst->xgs = src->gregs[REG_GS];
	dst->eip = src->gregs[REG_EIP];
	dst->xcs = src->gregs[REG_CS];
	dst->eflags = src->gregs[REG_EFL];
	dst->esp = src->gregs[REG_UESP];
	dst->xss = src->gregs[REG_SS];
#elif defined(__arm__)
	int n = 0;

	/*
	 * If this assert fails (which seems likely at some point) then
	 * registers have been added, so they'll need to be accounted for.
	 * See sys/user.h:struct user_regs for the definition.
	 */
	assert(sizeof (struct user_regs) / sizeof (unsigned long int) == 18);

	dst->uregs[n++] = src->arm_r0;
	dst->uregs[n++] = src->arm_r1;
	dst->uregs[n++] = src->arm_r2;
	dst->uregs[n++] = src->arm_r3;
	dst->uregs[n++] = src->arm_r4;
	dst->uregs[n++] = src->arm_r5;
	dst->uregs[n++] = src->arm_r6;
	dst->uregs[n++] = src->arm_r7;
	dst->uregs[n++] = src->arm_r8;
	dst->uregs[n++] = src->arm_r9;
	dst->uregs[n++] = src->arm_r10;
	dst->uregs[n++] = src->arm_fp;
	dst->uregs[n++] = src->arm_ip;
	dst->uregs[n++] = src->arm_sp;
	dst->uregs[n++] = src->arm_lr;
	dst->uregs[n++] = src->arm_pc;
	dst->uregs[n++] = src->arm_cpsr;

	/*
	 * XXX ORIG_r0 (see asm/ptrace.h)?
	 * Alternatively, this could also be sigcontext.fault_address
	 */
	dst->uregs[n++] = src->arm_r0;
#endif
}

void
ucore_getsig(siginfo_t *sip)
{
	bcopy(&ucore.c_sig, sip, sizeof (*sip));
}


void *
ucore_page_alloc(void)
{
	return (vmem_alloc(vmem_page, ucore_pgsize, VM_SLEEP));
}

void
ucore_page_free(void *buf)
{
	vmem_free(vmem_page, buf, ucore_pgsize);
}

static void
__attribute__ ((format(printf, 1, 0)))
ucore_vprintf(const char *format, va_list ap)
{
	(void) vsnprintf(ucore_vbuf, ucore_vlen, format, ap);
	(void) write(STDERR_FILENO, ucore_vbuf, strlen(ucore_vbuf));
}

static void
__attribute__ ((format(printf, 1, 2)))
ucore_printf(const char *format, ...)
{
	va_list ap;

	va_start(ap, format);
	ucore_vprintf(format, ap);
	va_end(ap);
}

static int
__attribute__ ((format(printf, 2, 0)))
ucore_verror(int err, const char *format, va_list ap)
{
	ucore_printf("\rucore error: ");
	ucore_vprintf(format, ap);
	ucore_printf(": %s\n", strerror(err));

	errno = err;
	return (-1);
}

int
__attribute__ ((format(printf, 2, 3)))
ucore_error(int err, const char *format, ...)
{
	va_list ap;

	va_start(ap, format);
	err = ucore_verror(err, format, ap);
	va_end(ap);

	return (err);
}

ssize_t
ucore_note_size(NElf_Word type, const char *name, size_t dlen)
{
	return (dlen == (size_t)-1 ? 0 : sizeof (NElf_Nhdr) +
	    P2ROUNDUP(strlen(name) + 1, sizeof (int32_t)) +
	    P2ROUNDUP(dlen, sizeof (int32_t)));
}

ssize_t
ucore_note_dump(int fd, off_t off,
    NElf_Word type, const char *name, const void *data, size_t dlen)
{
	ssize_t nlen = ucore_note_size(type, name, 0);
	NElf_Nhdr *note = alloca(nlen);

	struct iovec iov[2];
	int ioc = 0;

	if (dlen == (size_t)-1)
		return (-1); /* propagate caller's error */

	bzero(note, nlen);
	bcopy(name, note + 1, strlen(name));

	note->n_namesz = strlen(name) + 1;
	note->n_descsz = dlen;
	note->n_type = type;

	iov[ioc].iov_base = note;
	iov[ioc++].iov_len = nlen;

	iov[ioc].iov_base = (void *)data;
	iov[ioc++].iov_len = dlen;

	return (pwritev(fd, iov, ioc, off));
}

ssize_t
ucore_note_regs(NElf_Word type, int fd, off_t off,
    pid_t tid, const char *name, size_t size)
{
	struct iovec iov;

	iov.iov_base = alloca(size);
	bzero(iov.iov_base, size);
	iov.iov_len = size;

	if (ptrace(PTRACE_GETREGSET, tid, type, &iov) == -1) {
		(void) ucore_error(errno,
		    "failed to get regset 0x%x for TID %d", type, tid);
	}

	return (ucore_note_dump(fd, off, type, name, iov.iov_base, size));
}

static pid_t
ucore_thr_iter(void)
{
	if (ucore_threads != NULL)
		(void) rewinddir(ucore_threads);

	return (ucore.c_tid);
}

static pid_t
ucore_thr_next(void)
{
	struct dirent e, *dp = NULL;
	pid_t tid;

	if (ucore_threads == NULL)
		return (0);

	while (readdir_r(ucore_threads, &e, &dp) == 0 && dp != NULL) {
		if (dp->d_name[0] != '.' &&
		    (tid = atoi(dp->d_name)) != ucore.c_tid)
			return (tid);
	}

	return (0);
}

ssize_t
__attribute__ ((format(printf, 4, 5)))
ucore_slurp(int mode, char *buf, size_t len, const char *fmt, ...)
{
	char path[PATH_MAX];
	va_list ap;
	ssize_t rlen;
	int fd;

	if (buf == NULL)
		return (ucore_error(ENOMEM, "failed to alloc buf"));

	va_start(ap, fmt);
	(void) vsnprintf(path, sizeof (path), fmt, ap);
	va_end(ap);

	if ((fd = open(path, O_RDONLY)) == -1)
		return (ucore_error(errno, "failed to open %s", path));

	rlen = read(fd, buf, len);
	if (rlen > 0 && mode == UCORE_S_STR && buf[rlen - 1] == '\n')
		buf[--rlen] = '\0';

	(void) close(fd);
	return (rlen);
}

int
__attribute__ ((format(printf, 3, 4)))
ucore_parse(int (*func)(size_t, char *[], void *), void *farg,
    const char *fmt, ...)
{
	char path[PATH_MAX];
	va_list ap;

	int fd, err = 0;
	int line = 1;

	const char delims[] = " \f\n\r\t\v";
	char *eol, *eob, *rpos, *wpos;
	ssize_t len = 0;

	va_start(ap, fmt);
	(void) vsnprintf(path, sizeof (path), fmt, ap);
	va_end(ap);

	if ((fd = open(path, O_RDONLY)) == -1)
		return (ucore_error(errno, "failed to parse %s", path));

	eob = ucore_pbuf + ucore_plen - 1;
	rpos = wpos = ucore_pbuf;
	*wpos = '\0';

	do {
		char *argv[48] = { 0 };
		size_t argc = 0;
		char *p, *q;

		if ((eol = strchr(rpos, '\n')) != NULL) {
			*eol++ = '\0';
		} else {
			(void) memmove(ucore_pbuf, rpos, wpos - rpos);
			wpos -= rpos - ucore_pbuf;
			rpos = ucore_pbuf;

			if ((len = read(fd, wpos, eob - wpos)) < 0)
				break;

			wpos += len;
			*wpos = '\0';

			if (len > 0)
				continue;	/* retry EOL search */
		}

		for (p = strtok_r(rpos, delims, &q); p != NULL &&
		    argc < sizeof (argv) / sizeof (argv[0]);
		    p = strtok_r(NULL, delims, &q))
			argv[argc++] = p;

		if (argc != 0 && func(argc, argv, farg) != 0) {
			(void) ucore_error(errno,
			    "error at line %d of %s", line, path);

			if (errno == EPIPE || errno == EBADF)
				break; /* slave exited; abort the parse */
		}

		rpos = eol;
		line++;
	} while (rpos != NULL);

	if (len == -1)
		err = ucore_error(errno, "failed to parse %s", path);

	(void) close(fd);
	return (err);
}

/*
 * Generate the core file name into the specified pathname buffer from the
 * specified pattern.  We support the same set of specifiers as the Linux
 * kernel (which are spuriously different from the Solaris set from which
 * this entire concept originated), and also the extension %T to format the
 * current time as ISO 8601 instead of an integer (another win for userland).
 */
static void
ucore_name(const char *pat, char *buf, size_t len)
{
	char exe[PATH_MAX];
	struct tm tm;
	char ts[32];

	ssize_t rlen;
	const char *p;
	char c;

	char *q = buf;
	char *r = buf + len;

	if (pat == NULL || *pat == '\0')
		pat = "core"; /* default if nothing else configured */

	for (p = pat; q < r && (c = *p) != '\0'; p++) {
		if (c != '%') {
			*q++ = c;
			continue;
		}

		switch (*++p) {
		case '\0':
			p--;
			break;
		case '%':
			*q++ = c;
			break;
		case 'c':
			q += snprintf(q, (size_t)(r - q),
			    "%ju", (uintmax_t)ucore.c_lim.rlim_cur);
			break;
		case 'e':
		case 'E':
			if (*p == 'e')
				rlen = ucore_slurp(UCORE_S_STR, exe,
				    sizeof (exe), "/proc/self/comm");
			else
				rlen = readlink("/proc/self/exe",
				    exe, sizeof (exe));

			if (rlen == -1)
				(void) strcpy(exe, "a.out");

			for (char *d = exe; *d != '\0'; d++) {
				if (*d == '/')
					*d = '!';
			}

			q += snprintf(q, (size_t)(r - q), "%s", exe);
			break;
		case 'g':
			q += snprintf(q, (size_t)(r - q), "%d", ucore.c_gid);
			break;
		case 'h':
			q += snprintf(q, (size_t)(r - q),
			    "%s", ucore.c_uts.nodename);
			break;
		case 'u':
			q += snprintf(q, (size_t)(r - q), "%d", ucore.c_uid);
			break;
		case 'p':
			q += snprintf(q, (size_t)(r - q), "%d", ucore.c_pid);
			break;
		case 's':
			q += snprintf(q, (size_t)(r - q),
			    "%d", ucore.c_sig.si_signo);
			break;
		case 't':
			q += snprintf(q, (size_t)(r - q),
			    "%lu", ucore.c_tod.tv_sec);
			break;
		case 'T':
			if (localtime_r(&ucore.c_tod.tv_sec, &tm) == NULL ||
			    strftime(ts, sizeof (ts), "%FT%T", &tm) == 0)
				q += snprintf(q, (size_t)(r - q),
				    "%lu", ucore.c_tod.tv_sec);
			else
				q += snprintf(q, (size_t)(r - q), "%s", ts);
		}
	}

	if (q < r)
		*q = '\0';
	else if (len != 0)
		buf[len - 1] = '\0';
}

static int
ucore_dump_make_phdr(size_t argc, char *argv[], NElf_Phdr *php)
{
	uintptr_t p, q;
	char r, w, x;

	if (argc < 1 || sscanf(argv[0], "%" SCNxPTR "-%" SCNxPTR, &p, &q) != 2)
		return (ucore_error(EINVAL, "invalid address: %s", argv[0]));

	if (argc < 2 || sscanf(argv[1], "%c%c%c", &r, &w, &x) != 3)
		return (ucore_error(EINVAL, "invalid perms: %s", argv[1]));

	php->p_type = PT_LOAD;
	php->p_offset = 0;
	php->p_vaddr = p;
	php->p_paddr = 0;
	php->p_memsz = q - p;
	php->p_flags = 0;
	php->p_align = ucore_pgsize;

	if (r == 'r')
		php->p_flags |= PF_R;
	if (w == 'w')
		php->p_flags |= PF_W;
	if (x == 'x')
		php->p_flags |= PF_X;

	if (argc >= 6 && strcmp(argv[5], "[vsyscall]") == 0)
		php->p_filesz = 0;
	else if (r == '-')
		php->p_filesz = 0;
	else if (ucore_excl_mapping(php))
		php->p_filesz = 0;
	else
		php->p_filesz = q - p;

	return (0);
}

static int
ucore_dump_send_phdr(size_t argc, char *argv[], void *data)
{
	NElf_Phdr phdr;

	if (ucore_dump_make_phdr(argc, argv, &phdr) != 0)
		return (-1);

	if (write(ucore_pipe[UCORE_W], &phdr, sizeof (phdr)) != sizeof (phdr))
		return (ucore_error(errno, "failed to send phdr: %s", argv[0]));

	return (0);
}

static size_t
ucore_dump_send_datav(int fd, void *base, size_t size)
{
	ssize_t len;
	size_t sent;

	for (sent = 0; sent < size; sent += len) {
		struct iovec iov = {
			.iov_base = base + sent,
			.iov_len = size - sent,
		};
		if ((len = vmsplice(fd, &iov, 1, 0)) <= 0)
			break;
	}

	return (sent);
}

static int
ucore_dump_send_data(size_t argc, char *argv[], void *data)
{
	NElf_Phdr phdr;
	size_t size, sent;
	void *base, *buf;

	if (ucore_dump_make_phdr(argc, argv, &phdr) != 0)
		return (-1);

	base = (void *)phdr.p_vaddr;
	size = phdr.p_filesz;

	sent = ucore_dump_send_datav(ucore_pipe[UCORE_W], base, size);

	/*
	 * If vmsplice() failed due to EFAULT, this may be an MMIO region or
	 * kmalloc() memory remapped into user space that the kernel cannot
	 * pull directly into the filesystem. Attempt to make a local copy
	 * in typical userspace memory and send to the kernel.
	 */
	if (size != 0 && sent == 0 && errno == EFAULT) {
		size_t len = P2ROUNDUP(size, ucore_pgsize);

		if ((buf = mmap(NULL, len, PROT_READ | PROT_WRITE,
		    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0)) != MAP_FAILED) {
			sent = ucore_dump_send_datav(ucore_pipe[UCORE_W],
			    memcpy(buf, base, size), size);

			munmap(buf, len);
		}
	}

	if (sent != size) {
		(void) ucore_error(errno, "failed to send %s %s (%zu of %zu)",
		    argv[0], argv[1], sent, size);
		/*
		 * If we get any error, stop.
		 */
		return (-1);
	}

	return (0);
}

static void
ucore_dump_intr(int sig)
{
	if (__sync_fetch_and_add(&ucore_intr, 1) == 0)
		(void) close(ucore_pipe[UCORE_W]);
}

static int
ucore_dump_send(const struct ucore *cp)
{
	NElf_Phdr phdr;
	struct sigaction act;

	/*
	 * Before starting i/o, set up a signal handler and unblock SIGINT,
	 * so that the user can interrupt core dumps with ^C or kill -INT.
	 */
	act.sa_flags = 0;
	act.sa_handler = ucore_dump_intr;

	(void) sigprocmask(SIG_SETMASK, NULL, &act.sa_mask);
	(void) sigdelset(&act.sa_mask, SIGINT);
	(void) sigaction(SIGINT, &act, NULL);
	(void) sigprocmask(SIG_SETMASK, &act.sa_mask, NULL);

	bzero(&phdr, sizeof (phdr));
	phdr.p_type = PT_NULL;

	if (write(ucore_pipe[UCORE_W], cp, sizeof (*cp)) != sizeof (*cp))
		return (ucore_error(errno, "failed to send ucore"));

	if (ucore_parse(ucore_dump_send_phdr, NULL, "/proc/self/maps") != 0)
		return (ucore_error(errno, "failed to send Phdrs"));

	if (write(ucore_pipe[UCORE_W], &phdr, sizeof (phdr)) != sizeof (phdr))
		return (ucore_error(errno, "failed to send Phdr"));

	if (ucore_parse(ucore_dump_send_data, NULL, "/proc/self/maps") != 0)
		return (ucore_error(errno, "failed to send maps"));

	/*
	 * The child will need to gather additional data from this process
	 * after receiving our address space content.	We cannot continue
	 * until we are sure that has happened.  The child will try to hit
	 * us with SIGINT to interrupt this waitpid early, so we can skip
	 * waiting for the kernel to flush i/o on _exit.
	 */
	(void) waitpid(ucore_child, NULL, 0);

	return (0);
}

/*
 * For write errors close and unlink output and return the
 * result of ucore_error all in one go.
 */
static int
ucore_cnunr(int err, const char *errmsg, int fd, const char *path)
{
	(void) close(fd);
	(void) unlink(path);
	return (ucore_error(err, errmsg));
}

static int
ucore_dump_recv(const char *pattern)
{
	int rfd, wfd, pfd;
	ssize_t wlen, plen, slen;
	loff_t woff;
	size_t wres;

	uint64_t wnsec = 0;
	size_t wsum = 0;
	size_t wtot = 0;

	NElf_Ehdr ehdr;
	NElf_Word shnum, phnum;
	NElf_Phdr phdr, *pbuf;
	NElf_Word shidx = 0;
	NElf_Shdr *shdr = NULL;

	const ucore_note_t *n;
	char path[PATH_MAX];
	pid_t tid;

	rfd = ucore_pipe[UCORE_R];
	ucore_name(pattern, path, sizeof (path));
	wfd = open(path, O_CREAT | O_RDWR | O_TRUNC, 0666);

	if (wfd == -1)
		return (ucore_error(errno, "failed to open %s", path));

	bzero(&ehdr, sizeof (ehdr));
	bcopy(ELFMAG, ehdr.e_ident, SELFMAG);

	ehdr.e_ident[EI_CLASS] = NELFCLASS;
	ehdr.e_ident[EI_DATA] = NELFDATA;
	ehdr.e_ident[EI_VERSION] = EV_CURRENT;
	ehdr.e_ident[EI_OSABI] = ELFOSABI_LINUX;

	ehdr.e_type = ET_CORE;
	ehdr.e_machine = NELFMACH;
	ehdr.e_version = EV_CURRENT;
	ehdr.e_phoff = sizeof (NElf_Ehdr);
	ehdr.e_ehsize = sizeof (NElf_Ehdr);
	ehdr.e_phentsize = sizeof (NElf_Phdr);
	ehdr.e_shentsize = sizeof (NElf_Shdr);

	phnum = 1; /* PT_NOTE */
	shnum = 0; /* see below */

	/*
	 * Phase 1: For each thread, for each note, call note_size() to compute
	 * the total size of the PT_NOTE segment we will need to generate.
	 */
	bzero(&phdr, sizeof (phdr));
	phdr.p_type = PT_NOTE;
	phdr.p_align = sizeof (NElf_Word);

	for (tid = ucore_thr_iter(); tid != 0; tid = ucore_thr_next()) {
		for (n = ucore_notes; n->note_size != NULL; n++)
			phdr.p_filesz += n->note_size(n->note_type, -1, 0, tid);
	}

	wtot = phdr.p_filesz;
	woff = ehdr.e_phoff;
	wlen = pwrite(wfd, &phdr, sizeof (phdr), woff);
	woff = woff + wlen;

	if (wlen != sizeof (phdr))
		return (ucore_cnunr(errno,
		    "failed to save phdr", wfd, path));

	/*
	 * Phase 2: Read the Phdrs sent over the pipe from our parent, until
	 * we see a PT_NULL.  We temporarily store these in our output file.
	 * Then read them all back again into one contiguous buffer (pbuf).
	 */
	for (; ; woff += sizeof (NElf_Phdr), wtot += phdr.p_filesz, phnum++) {
		if (read(rfd, &phdr, sizeof (phdr)) != sizeof (phdr))
			return (ucore_cnunr(errno,
			    "failed to recv phdr", wfd, path));

		if (phdr.p_type == PT_NULL)
			break;

		if (pwrite(wfd, &phdr, sizeof (phdr), woff) != sizeof (phdr))
			return (ucore_cnunr(errno,
			    "failed to save phdr", wfd, path));
	}

	plen = sizeof (NElf_Phdr) * phnum;
	pbuf = vmem_alloc(vmem_heap, plen, VM_SLEEP);

	if (pread(wfd, pbuf, plen, ehdr.e_phoff) != plen)
		return (ucore_cnunr(errno,
		    "failed to load phdr table", wfd, path));

	woff = P2ROUNDUP(woff, pbuf[0].p_align);
	pbuf[0].p_offset = woff;

	/*
	 * Phase 3: Iterate over the threads again and generate the PT_NOTE
	 * content.  Since we're going to use ptrace() for some of these items,
	 * we need to go attach the task parent first, and then its children.
	 */
	if (ptrace(PTRACE_ATTACH, ucore.c_pid, NULL, NULL) != 0)
		(void) ucore_error(errno, "failed to attach %d", ucore.c_pid);

	if (waitpid(ucore.c_pid, NULL, 0) == -1)
		(void) ucore_error(errno, "failed to wait on %d", ucore.c_pid);

	for (tid = ucore_thr_iter(); tid != 0; tid = ucore_thr_next()) {
		if (tid != ucore.c_pid &&
		    ptrace(PTRACE_ATTACH, tid, NULL, NULL) != 0)
			(void) ucore_error(errno, "failed to attach %d", tid);

		if (tid != ucore.c_pid && waitpid(tid, NULL, __WCLONE) == -1)
			(void) ucore_error(errno, "failed to wait on %d", tid);

		for (n = ucore_notes; n->note_size != NULL; n++) {
			wlen = n->note_dump(n->note_type, wfd, woff, tid);
			if (wlen <= 0)
				continue;
			woff = P2ROUNDUP(woff + wlen, sizeof (int32_t));
			wsum += wlen;
		}

		if (tid != ucore.c_pid &&
		    ptrace(PTRACE_DETACH, tid, NULL, NULL) != 0)
			(void) ucore_error(errno, "failed to detach %d", tid);
	}

	if (ucore_flags & UCORE_F_BANNER) {
		(void) fprintf(stderr, "\b\b\b\b%3.0f%%",
		    (double)wsum / (double)wtot * 100.0);
	}

	if (ptrace(PTRACE_DETACH, ucore.c_pid, NULL, NULL) != 0)
		(void) ucore_error(errno, "failed to detach %d", ucore.c_pid);

	/*
	 * Phase 4: For each Phdr other than our initial PT_NOTE, splice the
	 * address space content from the pipe into our output file at the
	 * appropriate offset, which we save in the Phdr's pbuf[p].p_offset.
	 */
	for (NElf_Word p = 1; p < phnum; p++) {
		woff = P2ROUNDUP(woff, pbuf[p].p_align);
		pbuf[p].p_offset = woff;

		for (wres = pbuf[p].p_filesz; wres != 0; wres -= wlen) {
			uint64_t t0 = gethrtime();

			wlen = splice(rfd, NULL, wfd, &woff,
			    wres > ucore_throttle ? ucore_throttle : wres,
			    SPLICE_F_MOVE | SPLICE_F_MORE);

			if (wlen == 0) {
				(void) __sync_fetch_and_add(&ucore_intr, 1);
				goto out; /* parent exited, likely SIGINT */
			}

			if (wlen < 0)
				break; /* report errno below and continue */

			wnsec += gethrtime() - t0;
			wsum += wlen;

			if (ucore_flags & UCORE_F_BANNER) {
				(void) fprintf(stderr, "\b\b\b\b%3.0f%%",
				    (double)wsum / (double)wtot * 100.0);
			}
		}

		if (wres != 0) {
			(void) ucore_error(errno, "recv phdr[%u] = %zu/%zu\n",
			    p, pbuf[p].p_filesz - wres, pbuf[p].p_filesz);
		}

		pbuf[p].p_filesz -= wres;
	}

	if (pwrite(wfd, pbuf, plen, ehdr.e_phoff) != plen)
		return (ucore_cnunr(errno,
		    "failed to update phdrs", wfd, path));

	/*
	 * Phase 5: Alloc the Shdrs array, and loop through our list of proc
	 * files to directly incorporate into the core file as string sections.
	 */
	shnum = 1 + ucore_nprocs + 1; /* SHT_NULL, ucore_procs, .shstrtab */
	slen = sizeof (NElf_Shdr) * shnum;
	shdr = vmem_zalloc(vmem_heap, slen, VM_SLEEP);

	shdr[shidx++].sh_type = SHT_NULL;
	shdr[shnum - 1].sh_size = 1; /* \0 */

	for (size_t i = 0; i < ucore_nprocs; i++, shidx++) {
		(void) snprintf(path, sizeof (path),
		    "/proc/%d/%s", ucore.c_pid, ucore_procs[i]);

		shdr[shidx].sh_name = shdr[shnum - 1].sh_size;
		shdr[shnum - 1].sh_size += strlen(ucore_procs[i]) + 1;
		shdr[shidx].sh_type = SHT_LOUSER;
		shdr[shidx].sh_offset = woff;
		shdr[shidx].sh_addralign = 1;

		if ((pfd = open(path, O_RDONLY)) == -1) {
			(void) ucore_error(errno, "failed to open %s", path);
			continue;
		}

		while ((wlen = read(pfd, path, sizeof (path))) > 0) {
			if ((wlen = pwrite(wfd, path, wlen, woff)) > 0) {
				shdr[shidx].sh_size += wlen;
				woff += wlen;
			}
		}

		(void) close(pfd);
	}

	shdr[shidx].sh_size += strlen(".shstrtab") + 1;
	shdr[shidx].sh_type = SHT_STRTAB;
	shdr[shidx].sh_offset = woff;
	shdr[shidx].sh_addralign = 1;

	/*
	 * Now loop back through the list of sections and compose the shstrtab
	 * string table, and write it out to wfd as the final section payload.
	 */
	if (shdr[shidx].sh_size != 0) {
		char *shstrtab = vmem_zalloc(vmem_heap, shdr[shidx].sh_size,
		    VM_SLEEP);
		char *p = shstrtab + 1;

		for (size_t i = 0; i < ucore_nprocs; i++) {
			(void) strcpy(p, ucore_procs[i]);
			p += strlen(p) + 1;
		}

		shdr[shidx].sh_name = (size_t)(p - shstrtab);
		(void) strcpy(p, ".shstrtab");

		wlen = pwrite(wfd, shstrtab, shdr[shidx].sh_size, woff);
		vmem_free(vmem_heap, shstrtab, shdr[shidx].sh_size);

		if (wlen != (ssize_t)shdr[shidx].sh_size)
			return (ucore_cnunr(errno,
			    "failed to write shstrtab", wfd, path));

		woff += shdr[shidx].sh_size;
	}

	/*
	 * If the number of Phdrs or Shdrs exceeds the 16-bit sizes originally
	 * spec'd out in the ELF header, then the 32-bit values are encoded in
	 * the SHT_NULL section header, which is always defined to be shdr[0].
	 * The details are in the Solaris Linker and Libraries Guide, Table 7-7.
	 */
	if (phnum >= PN_XNUM || shnum >= SHN_LORESERVE) {
		shdr[0].sh_size = shnum;
		shdr[0].sh_link = ehdr.e_shstrndx;
		shdr[0].sh_info = phnum;
	}

	ehdr.e_shoff = P2ROUNDUP(woff, sizeof (NElf_Word));
	wlen = pwrite(wfd, shdr, slen, ehdr.e_shoff);
	woff = ehdr.e_shoff + slen;

	if (wlen != slen)
		return (ucore_cnunr(errno,
		    "failed to update shdrs", wfd, path));

	/*
	 * Phase 6: Write out the final Elf_Ehdr to make this a valid ELF
	 * ET_CORE file, and report final size and i/o statistics.
	 */
out:
	ehdr.e_phnum = phnum >= PN_XNUM ? PN_XNUM : phnum;
	ehdr.e_shnum = shnum >= SHN_LORESERVE ? 0 : shnum;
	ehdr.e_shstrndx = shnum >= SHN_LORESERVE ? SHN_UNDEF : shnum - 1;

	if (pwrite(wfd, &ehdr, sizeof (ehdr), 0) != sizeof (ehdr))
		return (ucore_cnunr(errno,
		    "failed to update ehdr", wfd, path));

	if (ucore_flags & UCORE_F_BANNER) {
		(void) fprintf(stderr, "  %.2fMB  %.2fMB/s",
		    (double)woff / (double)U_MB,
		    (double)wsum / (double)U_MB / ((double)wnsec / FP_NANOSEC));

		if (ucore_intr != 0)
			(void) fprintf(stderr, " (interrupted)");

		(void) fprintf(stderr, "\n\n");
	}
	(void) kill(ucore.c_pid, SIGINT); /* poke parent's waitpid() */

	if (shdr != NULL)
		vmem_free(vmem_heap, shdr, slen);

	vmem_free(vmem_heap, pbuf, plen);

	return (0);
}

static void
ucore_banner(int sig, const siginfo_t *sip, const ucontext_t *ucp)
{
	const char *arg0 = basename(_dl_argv[0]);
	int alen = (int)strlen(arg0);
	char buf[1024];

	if (sig > 0 && sig < NSIG)
		(void) snprintf(buf, sizeof (buf), "SIG%s", sys_sigabbrev[sig]);
	else
		(void) snprintf(buf, sizeof (buf), "SIG#%d", sig);

	ucore_printf("\r\n\n%s %s ", arg0, buf);
	ucore_printf("PID %d TID %d THR %lx\n",
	    ucore.c_pid, ucore.c_tid, ucore.c_thr);

	ucore_printf("%*s ", alen, "");
	psiginfo(sip, NULL);
	ucore_printf("\n");

	(void) utrace_symbol(ucore_utrace,
	    (uintptr_t)UCORE_MC_REG_PC(&ucp->uc_mcontext), buf, sizeof (buf));
	ucore_printf("%*s %s( )\n", alen, "", buf);

	for (int i = 0; i < ucore.c_stkdepth; i++) {
		(void) utrace_symbol(ucore_utrace,
		    ucore.c_stk[i], buf, sizeof (buf));
		ucore_printf("%*s %s( )\n", alen, "", buf);
	}

	ucore_printf("\n");

	if (ucore_flags & UCORE_F_USER) {
		ucore_name(ucore_upath, ucore_epath, sizeof (ucore_epath));
		ucore_printf("Dumping core to: %s\n", ucore_epath);
		ucore_printf("    in progress:   0%%");
	}
}

static int
ucore_getpcstack(struct frame *fp, uintptr_t *pcstack, int pcstack_limit)
{
	struct frame *fpnext;
	int depth = 0;

	while (fp != NULL && depth < pcstack_limit) {
		pcstack[depth++] = fp->fr_savpc;
		fpnext = (struct frame *)fp->fr_savfp;
		if (fpnext <= fp || fpnext > fp + (1UL << 20) ||
		    !IS_P2ALIGNED(fpnext, sizeof (struct frame)))
			break;
		fp = fpnext;
	}

	return (depth);
}

static void
ucore_signal(int sig, siginfo_t *sip, void *arg)
{
	ucontext_t *ucp = arg;
	int err = errno;

	struct sigaction act;
	struct rlimit rlim;
	pid_t tid;

	while (__sync_val_compare_and_swap(&ucore_sig, 0, sig) != 0)
		(void) sigsuspend(&ucore_mask);

	ucore.c_tid = syscall(SYS_gettid);
	ucore.c_thr = pthread_self();
	ucore.c_cyc = gethrcycles();
	ucore.c_hrt = hrcyctons(ucore.c_cyc);

	(void) clock_gettime(CLOCK_REALTIME, &ucore.c_tod);
	(void) clock_gettime(CLOCK_MONOTONIC, &ucore.c_sys);

	for (tid = ucore_thr_iter(); tid != 0; tid = ucore_thr_next()) {
		if (tid != ucore.c_tid)
			(void) syscall(SYS_tgkill, ucore.c_pid, tid, SIGABRT);
	}

	ucore.c_errno = err;
	ucore.c_uid = getuid();
	ucore.c_gid = getgid();

	(void) getrlimit(RLIMIT_CORE, &ucore.c_lim);
	(void) uname(&ucore.c_uts);

	bcopy(sip, &ucore.c_sig, sizeof (*sip));
	bcopy(ucp, &ucore.c_ctx, sizeof (*ucp));

	ucore.c_stkdepth = ucore_getpcstack((struct frame *)
	    (uintptr_t)UCORE_MC_REG_FP(&ucp->uc_mcontext),
	    ucore.c_stk, sizeof (ucore.c_stk) / sizeof (uintptr_t));

	if (ucore_flags & UCORE_F_BANNER)
		ucore_banner(sig, sip, ucp);

	for (ucore_func_t *f = list_head(&ucore_func_list);
	    f != NULL; f = list_next(&ucore_func_list, f))
		f->c_func(f->c_farg);

	if (ucore_child == 0)
		err = ucore_error(ECHILD, "libucore peer got sig %d", sig);
	else if (ucore_child == -1)
		err = ucore_error(EAGAIN, "libucore peer did not initialize");
	else if (ucore_flags & UCORE_F_USER)
		err = ucore_dump_send(&ucore);
	else
		err = 0;

	/*
	 * If we did not or could not generate a user core, or if a kernel
	 * core was requested, try to get a kernel core.  Otherwise suppress
	 * the kernel core file by just lowering RLIMIT_CORE to zero bytes.
	 * We also must work around Linux's do_coredump() which, only when its
	 * coredump pattern is a pipe (|), treats rlim=1 as 0 and !=1 as INF.
	 */
	(void) getrlimit(RLIMIT_CORE, &rlim);
	if (err != 0 || (ucore_flags & UCORE_F_KERNEL))
		rlim.rlim_cur = rlim.rlim_max;
	else if (ucore_kpath[0] == '|')
		rlim.rlim_cur = 1;
	else
		rlim.rlim_cur = 0;
	(void) setrlimit(RLIMIT_CORE, &rlim);

	if (err != 0 || (ucore_flags & UCORE_F_KERNEL)) {
		ucore_name(ucore_kpath, ucore_epath, sizeof (ucore_epath));
		ucore_printf("\n\rDumping core to: %s [%s]\n",
		    ucore_epath, "in kernel");
	}

	/*
	 * If the signal was asynchronous, then re-raise it (with our mask
	 * still blocking it) such that it is redelivered upon handler return,
	 * at which point it now trigger SIG_DFL and exit the process.  We want
	 * to do this so that (a) our exit status reflects the correct reason
	 * for death, and (b) so that UCORE_F_KERNEL will reflect the state of
	 * the original failure, and not with a stack showing us in libucore.
	 *
	 * The Linux use of si_code is very inconsistent, making it hard to
	 * write a generic rule for sync vs. async signals, but since we're
	 * only focused on core-dump signals, it suffices to check if the
	 * signal came from another process (SI_USER) or if the generic kernel
	 * code (SI_KERNEL) is used instead of a more specific fault code.
	 */
	(void) sigemptyset(&act.sa_mask);
	act.sa_flags = 0;
	act.sa_handler = SIG_DFL;
	(void) sigaction(sig, &act, NULL);

	if (sip->si_code <= SI_USER || sip->si_code == SI_KERNEL)
		(void) pthread_kill(ucore.c_thr, sig);
}

static int
ucore_sigaction(struct sigaction *act)
{
	int err = 0;

	err |= sigaction(SIGQUIT, act, NULL);
	err |= sigaction(SIGILL, act, NULL);
	err |= sigaction(SIGABRT, act, NULL);
	err |= sigaction(SIGFPE, act, NULL);
	err |= sigaction(SIGSEGV, act, NULL);
	err |= sigaction(SIGBUS, act, NULL);
	err |= sigaction(SIGSYS, act, NULL);
	err |= sigaction(SIGTRAP, act, NULL);
	err |= sigaction(SIGXCPU, act, NULL);
	err |= sigaction(SIGXFSZ, act, NULL);

	return (err);
}

static int
ucore_init_sigs(void)
{
	struct sigaction act;

	(void) sigfillset(&ucore_mask);

	ucore_stack.ss_size = P2ROUNDUP(SIGSTKSZ * 4, ucore_pgsize);
	ucore_stack.ss_sp = mmap(NULL, ucore_stack.ss_size,
	    PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

	if (ucore_stack.ss_sp == MAP_FAILED)
		return (ucore_error(errno, "failed to map signal stack"));

	if (sigaltstack(&ucore_stack, NULL) != 0)
		return (ucore_error(errno, "failed to setup signal stack"));

	act.sa_flags = SA_SIGINFO | SA_ONSTACK;
	act.sa_sigaction = ucore_signal;
	act.sa_mask = ucore_mask;

	if (ucore_sigaction(&act) != 0)
		return (ucore_error(errno, "failed to setup signal handling"));

	return (0);
}

static int
ucore_fini_sigs(void)
{
	struct sigaction act;

	act.sa_flags = 0;
	act.sa_handler = SIG_DFL;
	(void) sigemptyset(&act.sa_mask);

	if (ucore_sigaction(&act) != 0)
		return (ucore_error(errno, "failed to clear signal handling"));

	ucore_stack.ss_flags = SS_DISABLE;

	if (sigaltstack(&ucore_stack, NULL) != 0)
		return (ucore_error(errno, "failed to clear signal stack"));

	if (ucore_stack.ss_sp != MAP_FAILED)
		(void) munmap(ucore_stack.ss_sp, ucore_stack.ss_size);

	return (0);
}

static int
ucore_init_peer(void)
{
	ssize_t rlen;
	int err, rw;

	if (pipe2(ucore_pipe, O_CLOEXEC) != 0)
		return (ucore_error(errno, "failed to open pipe"));

	if ((ucore_child = fork()) == -1)
		return (ucore_error(errno, "failed to fork peer"));

	rw = ucore_child ? UCORE_R : UCORE_W;
	(void) close(ucore_pipe[rw]);
	ucore_pipe[rw] = -1;

	if (ucore_child != 0)
		return (0); /* parent ready to continue */

	/*
	 * The ucore child now becomes its own pgid to avoid entangling itself
	 * with the parent's job control, blocks all extraneous signals to
	 * avoid outside interference, and waits for the parent to send us
	 * the initial core dump message, which consists of struct ucore.
	 */
	(void) setpgid(0, 0);
	(void) sigprocmask(SIG_SETMASK, &ucore_mask, NULL);

	do {
		rlen = read(ucore_pipe[UCORE_R], &ucore, sizeof (ucore));
	} while (rlen == -1 && errno == EINTR);

	/*
	 * If we have a valid message, start the dump.  Otherwise just exit.
	 * If we fail ucore_dump_recv(), exit status is errno for debugging.
	 */
	if (rlen == sizeof (ucore) && ucore_dump_recv(ucore_upath) != 0)
		err = errno;
	else if (rlen == -1)
		err = errno;
	else
		err = 0;

	_exit(err);
}

static int
ucore_init_opts(int flags, const char *o)
{
	int set, bit;
	const char *opt;
	char *e, *p, *q;
	size_t len;

	len = strlen(o);
	e = alloca(len + 1);
	(void) strcpy(e, o);

	for (p = strtok_r(e, ",", &q); p != NULL; p = strtok_r(NULL, ",", &q)) {
		if (strncmp(p, "no", 2) == 0) {
			opt = p + 2;
			set = 0;
			bit = 0;
		} else {
			opt = p;
			set = 1;
			bit = 0;
		}

		if (strcmp(opt, "user") == 0)
			bit = UCORE_F_USER;
		else if (strcmp(opt, "kernel") == 0)
			bit = UCORE_F_KERNEL;
		else if (strcmp(opt, "banner") == 0)
			bit = UCORE_F_BANNER;
		else if (strcmp(opt, "exclude") == 0)
			bit = UCORE_F_EXCLUDE;
		else if (strcmp(opt, "enable") == 0)
			bit = UCORE_F_ENABLE;
		else
			(void) ucore_error(EINVAL,
			    "ignoring unknown option: %s", opt);

		if (set != 0 && bit != 0) {
			flags |= bit;
		} else if (set == 0 && bit != 0) {
			flags &= ~bit;
			flags |= UCORE_F_NO(bit);
		}
	}

	return (flags);
}

void
ucore_include(const void *base, size_t size)
{
	NElf_Phdr k, *p, *q;

	k.p_vaddr = (NElf_Addr)base;
	k.p_memsz = size;

	(void) pthread_mutex_lock(&ucore_excl_mutex);

	if ((p = lfind(&k, ucore_excl_phdrs, &ucore_excl_valid,
	    sizeof (NElf_Phdr), (__compar_fn_t)ucore_excl_compare)) != NULL) {

		q = ucore_excl_phdrs + ucore_excl_count;
		bcopy(p + 1, p, (size_t)(q - p - 1) * sizeof (NElf_Phdr));
		ucore_excl_valid--;

		qsort(ucore_excl_phdrs, ucore_excl_valid,
		    sizeof (NElf_Phdr), (__compar_fn_t)ucore_excl_compare);
	}

	(void) pthread_mutex_unlock(&ucore_excl_mutex);
}

void
ucore_exclude(const void *base, size_t size)
{
	NElf_Phdr *p;

	(void) pthread_mutex_lock(&ucore_excl_mutex);

	if (ucore_excl_valid == ucore_excl_count) {
		size_t old_size = sizeof (NElf_Phdr) * ucore_excl_count;
		size_t new_size = old_size + sizeof (NElf_Phdr);

		NElf_Phdr *old_phdr = ucore_excl_phdrs;
		NElf_Phdr *new_phdr = vmem_zalloc(vmem_heap, new_size,
		    VM_SLEEP);

		bcopy(old_phdr, new_phdr, old_size);
		vmem_free(vmem_heap, old_phdr, old_size);

		ucore_excl_phdrs = new_phdr;
		ucore_excl_count++;
	}

	p = &ucore_excl_phdrs[ucore_excl_valid++];

	p->p_type = PT_LOAD;
	p->p_vaddr = (NElf_Addr)base;
	p->p_memsz = size ? size : 1;

	qsort(ucore_excl_phdrs, ucore_excl_valid,
	    sizeof (NElf_Phdr), (__compar_fn_t)ucore_excl_compare);

	(void) pthread_mutex_unlock(&ucore_excl_mutex);
}

ucore_handle_t
ucore_onfault(void (*func)(void *), void *farg)
{
	ucore_func_t *f = vmem_zalloc(vmem_heap, sizeof (*f), VM_SLEEP);

	f->c_func = func;
	f->c_farg = farg;

	(void) pthread_mutex_lock(&ucore_func_mutex);
	list_insert_tail(&ucore_func_list, f);
	(void) pthread_mutex_unlock(&ucore_func_mutex);
	return ((ucore_handle_t)f);
}

void
ucore_nofault(ucore_handle_t h)
{
	ucore_func_t *f = (ucore_func_t *)h;

	if (f != NULL) {
		(void) pthread_mutex_lock(&ucore_func_mutex);
		list_delete(&ucore_func_list, f);
		(void) pthread_mutex_unlock(&ucore_func_mutex);
		vmem_free(vmem_heap, f, sizeof (*f));
	}
}

static void
ucore_atfork_child(void)
{
	ucore.c_pid = getpid();

	if ((ucore_flags & UCORE_F_USER) != 0) {
		ucore_flags &= ~UCORE_F_USER;
		if ((ucore_flags & UCORE_F_NO(UCORE_F_KERNEL)) == 0)
			ucore_flags |= UCORE_F_KERNEL;
	}
}

static void
__attribute__ ((constructor))
ucore_init(void)
{
	const char *e;

	ucore.c_pid = getpid();
	ucore.c_tid = -1;

	ucore_utrace = utrace_open_self();
	ucore_threads = opendir("/proc/self/task");
	ucore_pgsize = sysconf(_SC_PAGESIZE);
	ucore_clktck = sysconf(_SC_CLK_TCK);

	list_init(&ucore_func_list, offsetof(ucore_func_t, c_list));

	if (isatty(fileno(stderr)))
		ucore_flags |= UCORE_F_BANNER;

	if ((e = getenv("UCORE_OPTIONS")) != NULL)
		ucore_flags = ucore_init_opts(ucore_flags, e);

	if ((ucore_flags & UCORE_F_NO(UCORE_F_ENABLE)) != 0 ||
	    (ucore_flags & UCORE_F_ENABLE) == 0 && !ucore_enable)
		return;

	if (ucore_slurp(UCORE_S_STR, ucore_kpath,
	    sizeof (ucore_kpath), "/proc/sys/kernel/core_pattern") <= 0)
		(void) strcpy(ucore_kpath, "core.%p");

	if (ucore_kpath[0] != '|')
		(void) strcpy(ucore_upath, ucore_kpath);
	else
		(void) strcpy(ucore_upath, "core.%p");

	if ((e = getenv("UCORE_PATH")) != NULL && *e != '|')
		(void) strncpy(ucore_upath, e, sizeof (ucore_upath) - 1);

	if (ucore_init_sigs() != 0 || ucore_init_peer() != 0)
		(void) ucore_error(errno, "ucore_init() failed");
	else
		(void) pthread_atfork(NULL, NULL, ucore_atfork_child);
}

static void
__attribute__ ((destructor))
ucore_fini(void)
{
	ucore_func_t *f;

	if (ucore_fini_sigs() != 0)
		(void) ucore_error(errno, "ucore_fini() failed");

	for (int rw = 0; rw < 2; rw++)
		(void) close(ucore_pipe[rw]);

	if (ucore_threads != NULL)
		(void) closedir(ucore_threads);

	vmem_free(vmem_heap, ucore_excl_phdrs,
	    sizeof (NElf_Phdr) * ucore_excl_count);

	while ((f = list_head(&ucore_func_list)) != NULL)
		ucore_nofault(f);

	list_fini(&ucore_func_list);
	utrace_close(ucore_utrace);
}
