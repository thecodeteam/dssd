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

#ifndef	_UCORE_IMPL_H
#define	_UCORE_IMPL_H

/*
 * ucore_impl.h - include file for nt_*.c implementations
 *
 * At present, linux/elfcore.h defines the structures shared between the
 * Linux kernel core dump code and its consumer, gdb.  This file in turn
 * requires other kernel source files to compile, making for quite a mess: it
 * appears the mental model here is just copying structs and not an interface.
 * Also, elfcore.h can only compile with the kernel's elf.h, not userland elf.h.
 *
 * The following hacks make it possible to compile our nt_*.c source against
 * linux/elfcore.h without becoming an entire kernel compilation environment.
 * This is brittle and stupid, but the only alternative is struct duplication.
 * If this .h file starts to break frequently, that may be a better alternative.
 */

#include <unistd.h>
#include <malloc.h>

#if defined(__arm__)
/* The user struct names are different/missing on ARM compared to x86 */
#define user_regs_struct user_regs
#define user_fpregs_struct user_fpregs
struct user_fpxregs_struct
{
};
#endif  /* __arm__ */

#if defined(_ELF_H)
#include <sys/types.h>
#include <sys/user.h>
#else
#include <bits/types.h>
#include <sys/user.h>

typedef __pid_t pid_t;
typedef __ssize_t ssize_t;
typedef __UWORD_TYPE size_t;

typedef unsigned long elf_greg_t;
typedef struct user_regs_struct elf_gregset_t;
typedef struct user_fpregs_struct elf_fpregset_t;
typedef struct user_fpxregs_struct elf_fpxregset_t;

#include <linux/elfcore.h>
#include <linux/ptrace.h>
#endif

#include <nelf.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * <sys/ptrace.h> is mostly just needless duplication of the contents of
 * <linux/ptrace.h>, save for the ptrace(2) prototype itself.  On older
 * Linux versions, they can both be included (if done in the right order),
 * but this fragile arrangement breaks on newer kernels.  We define ptrace(2)
 * ourselves here so we can avoid <sys/ptrace.h> and use <linux/ptrace.h>
 * (which is included transitively outside our control).
 */
extern long int ptrace(int, ...);

/*
 * Interfaces between core file note generators and the common libucore code.
 * Notes must provide two functions: note_size(), to just report the size of
 * the note in bytes, and note_dump(), to actually write out the data buffer.
 */
typedef ssize_t ucore_note_f(NElf_Word, int, off_t, pid_t);

typedef struct ucore_note {
	NElf_Word note_type;
	ucore_note_f *note_size;
	ucore_note_f *note_dump;
} ucore_note_t;

extern size_t ucore_pgsize;	/* _SC_PAGESIZE */
extern long ucore_clktck;	/* _SC_CLK_TCK */

extern pid_t ucore_getpid(void);
extern pid_t ucore_gettid(void);
extern void ucore_getreg(struct user_regs_struct *);
extern void ucore_getsig(siginfo_t *);
extern void *ucore_page_alloc(void);
extern void ucore_page_free(void *);

extern int ucore_error(int, const char *, ...)
    __attribute__ ((format(printf, 2, 3)));

#define	UCORE_S_STR	1	/* slurp string */
#define	UCORE_S_BIN	2	/* slurp binary */

extern ssize_t ucore_slurp(int, char *, size_t, const char *, ...)
    __attribute__ ((format(printf, 4, 5)));

extern int ucore_parse(int (*)(size_t, char *[], void *), void *,
    const char *, ...) __attribute__ ((format(printf, 3, 4)));

extern ssize_t ucore_note_size(NElf_Word, const char *, size_t);
extern ssize_t ucore_note_dump(int, off_t,
    NElf_Word, const char *, const void *, size_t);
extern ssize_t ucore_note_regs(NElf_Word, int, off_t,
    pid_t, const char *, size_t);

extern ucore_note_f nt_prstatus_size;
extern ucore_note_f nt_prstatus_dump;
extern ucore_note_f nt_prpsinfo_size;
extern ucore_note_f nt_prpsinfo_dump;
extern ucore_note_f nt_auxv_size;
extern ucore_note_f nt_auxv_dump;
extern ucore_note_f nt_fpregset_size;
extern ucore_note_f nt_fpregset_dump;
extern ucore_note_f nt_prxfpreg_size;
extern ucore_note_f nt_prxfpreg_dump;
extern ucore_note_f nt_xstate_size;
extern ucore_note_f nt_xstate_dump;

#ifdef	__cplusplus
}
#endif

#endif	/* _UCORE_IMPL_H */
