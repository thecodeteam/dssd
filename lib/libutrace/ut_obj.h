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

#ifndef	_UT_OBJ_H
#define	_UT_OBJ_H

#ifdef	__cplusplus
extern "C" {
#endif

typedef struct ut_obj {
	pthread_mutex_t utob_prlock;
	utrace_probe_t *utob_probev;
	size_t utob_probec;
	uint32_t utob_refs;
	void *utob_symtab;
	size_t utob_symlen;
	size_t utob_syment;
	char *utob_strtab;
	size_t utob_strlen;
} ut_obj_t;

extern void utrace_obj_init(ut_obj_t *);
extern int utrace_obj_load(utrace_handle_t *, ut_obj_t *, const char *);
extern void utrace_obj_free(ut_obj_t *);
extern void utrace_obj_hold(ut_obj_t *);
extern void utrace_obj_rele(ut_obj_t *);
extern size_t utrace_obj_name(ut_obj_t *, uintptr_t, char *, size_t);

#ifdef	__cplusplus
}
#endif

#endif	/* _UT_OBJ_H */
