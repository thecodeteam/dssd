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

#ifndef	_UTRACE_H
#define	_UTRACE_H

#include <stdint.h>
#include <stdarg.h>
#include <stdio.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * UTrace Profile Callback Definitions
 */
typedef void utrace_prof_begin_f(unsigned slot);
typedef void utrace_prof_end_f(unsigned slot);

typedef struct utrace_prof_ops {
	utrace_prof_begin_f *utpf_begin;
	utrace_prof_end_f *utpf_end;
} utrace_prof_ops_t;

/*
 * UTrace Probe Definition
 *
 * This structure corresponds to the metadata recorded in the instrumented
 * program's .utrace ELF section, and can be retrieved using utrace_walk().
 */
typedef struct utrace_probe {
	void *prb_head;
	void *prb_tail;
	uint32_t prb_prid;
	uint32_t prb_line;
	const char *prb_file;
	const char *prb_event;
	const char *prb_fmt;
	void *prb_src;
	void *prb_dst;
} utrace_probe_t;

/*
 * UTrace Probe Implementation
 *
 * NOTE: The following definitions are private to utrace but must be exported
 * in this .h file such that consuming code compiles using it.
 *
 * Defines for building our static trace macro: declare the assembler pseudo-
 * op corresponding to sizeof (void *), macros for cpp recursive definitions,
 * and then the architecture-specific byte sequence for a 5-byte no-op.
 */

#if defined(__i386__) || defined(__x86_64__)

#if __WORDSIZE == 64
#define	utrace_probe_ptr		".quad "
#else
#define	utrace_probe_ptr		".long "
#endif

#define	utrace_probe_str(s)	#s
#define	utrace_probe_lbl(i, j)	_utrace_probe_##i##_##j
#define	utrace_probe_def(i, j)	"_utrace_probe_" utrace_probe_str(i) j

#define	utrace_probe_nopb	0x0F, 0x1F, 0x44, 0x00, 0x00
#define	utrace_probe_nops	"0x0F, 0x1F, 0x44, 0x00, 0x00"

/*
 * UTrace Probe GCC Kung Fu
 *
 * The number of syntactic tricks going on here makes this basically write-
 * only, so let's try to explain in English what is going on here:
 *
 * - declare a local static of the format string in C with an assembler label,
 *   because format strings use % which is an asm goto syntactic metacharacter
 * - declare a labeled "nop" (0) in the text section using asm goto( )
 * - declare in .rodata the file name and stringified event enumerator (1, 2)
 * - declare in .utrace an instantation of utrace_probe_t, in which we
 *   reference all of the above static data, along with the address of
 *   label (0) (the probe 'src') and the output label (%l0) (the probe 'dst')
 * - declare a goto label for an empty clause immediately following asm goto
 * - declare a global extern of the utrace_probe_t we declared in assembly
 * - under if(0) call _utrace_probe() with all the arguments, and goto %l0
 *
 * The result of our kung-fu is that we get the impossible dream of statically-
 * defined yet dynamically-enabled source-aware instrumentation:
 *
 * - a nop that will "stick" in gcc's assembly of the calling function,
 *   and not be removed by any subsequent optimization passes.
 *
 * - a .utrace probe structure with a text relocation to resolve the address
 *   of the nop we want to patch, and the site of the _utrace_probe() call.
 *
 * - a chunk of code to assemble arguments to call _utrace_probe(), which is
 *   reachable from the asm goto (and thus cannot be removed by dead-code
 *   elimination) but appears unreachable and thus is moved to the end of the
 *   caller's code, thereby removing it from the normal i-cache footprint.
 */
#define	utrace_probe(pfid, file, line, func, evt, fmt, ...)	\
	do { 						\
		static const char utrace_probe_lbl(pfid, f)[] \
		    asm(utrace_probe_def(pfid, "_f")) = fmt; \
		asm goto(				\
		    "0: .byte " utrace_probe_nops ";"	\
		    ".pushsection .rodata;"		\
		    "1: .string \"" file "\";"		\
		    "2: .string \"" utrace_probe_str(evt) "\";" \
		    ".popsection;"			\
		    ".pushsection .utrace;"		\
		    utrace_probe_def(pfid, "_d") ":" 	\
		    utrace_probe_ptr "0, 0;"		\
		    ".long " utrace_probe_str(pfid) ";"	\
		    ".long " utrace_probe_str(line) ";"	\
		    utrace_probe_ptr "1b, 2b;"		\
		    utrace_probe_ptr utrace_probe_def(pfid, "_f") ";" \
		    utrace_probe_ptr "0b, %l0;"		\
		    ".popsection;"			\
		    :::: utrace_probe_lbl(pfid, 0));	\
		utrace_probe_lbl(pfid, 1):		\
		    ; /* site of the post-probe goto */	\
		if (0) {				\
		    _Pragma("GCC diagnostic push")	\
		    _Pragma("GCC diagnostic ignored \"-Wnested-externs\"") \
		    extern utrace_probe_t utrace_probe_lbl(pfid, d); \
		    _Pragma("GCC diagnostic pop")	\
		    utrace_probe_lbl(pfid, 0):		\
			_utrace_probe(&utrace_probe_lbl(pfid, d), func, evt, \
			    utrace_probe_lbl(pfid, f), ##__VA_ARGS__); \
		    goto utrace_probe_lbl(pfid, 1);	\
		}					\
	} while (0)

/*
 * UTrace Probe Interface
 *
 * To statically instrument code, the calling program is responsible for
 * declaring an enumeration of event classes (enum utrace_event) and then
 * inserting calls of the form: utrace(MY_EVENT, "%s happened", "something");
 * into their C code.  These macros expand to the current source location
 * and the hot-patch location information defined by utrace_probe() above.
 */
#define	utrace(evt, fmt, ...) \
	utrace_probe(__COUNTER__, __FILE__, __LINE__, \
	__func__, evt, fmt, ##__VA_ARGS__)

#else

#define	utrace(evt, fmt, ...)

#endif  /* defined(__i386__) || defined(__x86_64__) */

typedef enum utrace_event utrace_event_t;
typedef struct utrace_handle utrace_handle_t;
typedef struct utrace_request utrace_request_t;

extern void * utrace_thread_init(size_t);
extern void utrace_thread_fini(void);

extern utrace_handle_t *utrace_open_self(void);
extern void utrace_close(utrace_handle_t *);

extern void _utrace_vprobe(utrace_probe_t *, const char *, utrace_event_t,
    const char *, va_list) __attribute__ ((format(printf, 4, 0)));

extern void _utrace_probe(utrace_probe_t *, const char *, utrace_event_t,
    const char *, ...) __attribute__ ((format(printf, 4, 5)));

typedef void utrace_probe_f(utrace_handle_t *, utrace_probe_t *, void *);
extern void utrace_walk(utrace_handle_t *, utrace_probe_f *, void *);
extern void utrace_list(utrace_handle_t *, utrace_probe_t *, void *);

extern utrace_request_t *utrace_fcompile(utrace_handle_t *, FILE *);
extern utrace_request_t *utrace_compile(utrace_handle_t *, const char *);

extern void utrace_enable(utrace_handle_t *, utrace_request_t *);
extern void utrace_disable(utrace_handle_t *);

extern size_t utrace_symbol(utrace_handle_t *, uintptr_t, char *, size_t);

typedef int utrace_print_f(FILE *, const char *, va_list)
  __attribute__((format(printf, 2, 0)));

typedef int utrace_trace_f(char *, size_t, const char *, va_list)
  __attribute__((format(printf, 3, 0)));

extern void utrace_redir_print(utrace_print_f *, FILE *);
extern void utrace_redir_trace(utrace_trace_f *);

extern void utrace_profile(utrace_prof_ops_t *ops);

#ifdef	__cplusplus
}
#endif

#endif	/* _UTRACE_H */
