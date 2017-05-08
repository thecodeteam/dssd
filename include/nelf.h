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
 * @fi nelf.h
 * @br Native ELF types @bc
 *
 * Overview
 * --------
 *
 * ELF type names pedantically include the word size.  Such precision
 * is rare and should be appreciated.  However, there are times when
 * needing to explicit refer to a specific version of an ELF structure
 * presents an undue maintenance burden.
 *
 * One case, where a single set of types is needed that is wide enough
 * to communicate ELF data regardless of native and target word-size,
 * is addressed by gelf.h.  On some operating systems, such as Solaris,
 * these types are accompanied by a set of library routines.
 *
 * This header addresses a second case, where code that is compiled for
 * multiple word-sizes needs a single set of types that refer to whatever
 * its native ELF definitions currently are.
 *
 * In a kindness to users of cscope, each typedef is listed explicitly.
 *
 * elf.h vs. elf.h
 * ---------------
 *
 * linux/elf.h and elf.h are incompatible, but our consumers may need
 * to use either.  Favoring plain elf.h users, we propose (and enforce)
 * the following contract:
 *
 *   We will normally include elf.h, so that nelf.h will always
 *   compile when included on its own.
 *
 *   If someone needs linux/elf.h, they must include it first.  If we
 *   see it has been included, we will *not* include elf.h, and will
 *   turn off the definitions that depend on elf.h
 *
 * While the file could be arranged to minimize the #ifndefs required,
 * it isn't.  Reasonable semantic grouping takes priority over catering
 * to the idiosyncrasies of Linux's implementation.
 *
 * @ec
 */

#ifndef	_NELF_H
#define	_NELF_H

#ifndef _LINUX_ELF_H
#include <elf.h>
#endif /* _LINUX_ELF_H */

#ifdef	__cplusplus
extern "C" {
#endif

#ifndef __BYTE_ORDER__
#include <endian.h>
#define __BYTE_ORDER__ __BYTE_ORDER
#define __ORDER_LITTLE_ENDIAN__ __LITTLE_ENDIAN
#define __ORDER_BIG_ENDIAN__ __BIG_ENDIAN
#endif

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define	NELFDATA	ELFDATA2LSB
#else
#define	NELFDATA	ELFDATA2MSB
#endif

#if defined(__x86_64__)
#define	NELFMACH	EM_X86_64
#elif defined(__i386__)
#define	NELFMACH	EM_386
#elif defined(__arm__)
#define	NELFMACH	EM_ARM
#else
#error unknown architecture
#endif

#ifdef _LP64

#define	NELFCLASS	ELFCLASS64

/* Base types */
typedef Elf64_Half	NElf_Half;
typedef Elf64_Sword	NElf_Sword;
typedef Elf64_Word	NElf_Word;
typedef Elf64_Xword	NElf_Xword;
typedef Elf64_Sxword	NElf_Sxword;

/* Abstract types */
typedef Elf64_Addr	NElf_Addr;
typedef Elf64_Off	NElf_Off;
#ifndef _LINUX_ELF_H
typedef Elf64_Section	NElf_Section;
#endif /* _LINUX_ELF_H */

/* Header types */
typedef Elf64_Ehdr	NElf_Ehdr;
typedef Elf64_Shdr	NElf_Shdr;
typedef Elf64_Nhdr	NElf_Nhdr;
typedef Elf64_Phdr	NElf_Phdr;

/* Symbols and relocation */
typedef Elf64_Sym	NElf_Sym;
#ifndef _LINUX_ELF_H
typedef Elf64_Syminfo	NElf_Syminfo;
typedef Elf64_Move	NElf_Move;
#endif /* _LINUX_ELF_H */
typedef Elf64_Rel	NElf_Rel;
typedef Elf64_Rela	NElf_Rela;

/* Dynamic linking support */
typedef Elf64_Dyn	NElf_Dyn;
#ifndef _LINUX_ELF_H
typedef Elf64_Verdef	NElf_Verdef;
typedef Elf64_Verdaux	NElf_Verdaux;
typedef Elf64_Verneed	NElf_Verneed;
typedef Elf64_Vernaux	NElf_Vernaux;
#endif /* _LINUX_ELF_H */

/* Aux vector */
#ifndef _LINUX_ELF_H
typedef Elf64_auxv_t	NElf_auxv_t;
#endif /* _LINUX_ELF_H */

/* Symbol macros */
#define	NELF_ST_BIND	ELF64_ST_BIND
#define	NELF_ST_TYPE	ELF64_ST_TYPE
#ifndef _LINUX_ELF_H
#define	NELF_ST_INFO	ELF64_ST_INFO
#define	NELF_ST_VISIBILITY	ELF64_ST_VISIBILITY
#endif /* _LINUX_ELF_H */

/* Relocation macros */
#define	NELF_R_SYM	ELF64_R_SYM
#define	NELF_R_TYPE	ELF64_R_TYPE
#ifndef _LINUX_ELF_H
#define	NELF_R_INFO	ELF64_R_INFO
#endif /* _LINUX_ELF_H */

/* Move macros */
#ifndef _LINUX_ELF_H
#define	NELF_M_SYM	ELF64_M_SYM
#define	NELF_M_SIZE	ELF64_M_SIZE
#define	NELF_M_INFO	ELF64_M_INFO
#endif /* _LINUX_ELF_H */

#else

#define	NELFCLASS	ELFCLASS32

/* Base types */
typedef Elf32_Half	NElf_Half;
typedef Elf32_Sword	NElf_Sword;
typedef Elf32_Word	NElf_Word;
#ifndef _LINUX_ELF_H
typedef Elf32_Xword	NElf_Xword;
typedef Elf32_Sxword	NElf_Sxword;
#endif /* _LINUX_ELF_H */

/* Abstract types */
typedef Elf32_Addr	NElf_Addr;
typedef Elf32_Off	NElf_Off;
#ifndef _LINUX_ELF_H
typedef Elf32_Section	NElf_Section;
#endif /* _LINUX_ELF_H */

/* Header types */
typedef Elf32_Ehdr	NElf_Ehdr;
typedef Elf32_Shdr	NElf_Shdr;
typedef Elf32_Nhdr	NElf_Nhdr;
typedef Elf32_Phdr	NElf_Phdr;

/* Symbols and relocation */
typedef Elf32_Sym	NElf_Sym;
#ifndef _LINUX_ELF_H
typedef Elf32_Syminfo	NElf_Syminfo;
typedef Elf32_Move	NElf_Move;
#endif /* _LINUX_ELF_H */
typedef Elf32_Rel	NElf_Rel;
typedef Elf32_Rela	NElf_Rela;

/* Dynamic linking support */
typedef Elf32_Dyn	NElf_Dyn;
#ifndef _LINUX_ELF_H
typedef Elf32_Verdef	NElf_Verdef;
typedef Elf32_Verdaux	NElf_Verdaux;
typedef Elf32_Verneed	NElf_Verneed;
typedef Elf32_Vernaux	NElf_Vernaux;
#endif /* _LINUX_ELF_H */

/* Aux vector */
#ifndef _LINUX_ELF_H
typedef Elf32_auxv_t	NElf_auxv_t;
#endif /* _LINUX_ELF_H */

/* Symbol macros */
#define	NELF_ST_BIND	ELF32_ST_BIND
#define	NELF_ST_TYPE	ELF32_ST_TYPE
#ifndef _LINUX_ELF_H
#define	NELF_ST_INFO	ELF32_ST_INFO
#define	NELF_ST_VISIBILITY	ELF32_ST_VISIBILITY
#endif /* _LINUX_ELF_H */

/* Relocation macros */
#define	NELF_R_SYM	ELF32_R_SYM
#define	NELF_R_TYPE	ELF32_R_TYPE
#ifndef _LINUX_ELF_H
#define	NELF_R_INFO	ELF32_R_INFO
#endif /* _LINUX_ELF_H */

/* Move macros */
#ifndef _LINUX_ELF_H
#define	NELF_M_SYM	ELF32_M_SYM
#define	NELF_M_SIZE	ELF32_M_SIZE
#define	NELF_M_INFO	ELF32_M_INFO
#endif /* _LINUX_ELF_H */

#endif

#ifdef	__cplusplus
}
#endif

#endif	/* _NELF_H */
