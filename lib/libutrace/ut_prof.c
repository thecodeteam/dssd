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

#include <utrace.h>
#include <utrace_impl.h>


/*
 * Default utrace profiling stub callbacks.
 */
static void
utrace_prof_begin(unsigned slot)
{
}

static void
utrace_prof_end(unsigned slot)
{
}

/*
 * The active utrace profiling ops.
 */
utrace_prof_ops_t UT_prof;

/*
 * Sets the utrace profiling callbacks.
 *
 * If ops is NULL then the default callbacks are set.
 */
void
utrace_profile(utrace_prof_ops_t *ops)
{
	if (ops != NULL) {
		(void) memcpy(&UT_prof, ops, sizeof (UT_prof));
	} else {
		UT_prof.utpf_begin = utrace_prof_begin;
		UT_prof.utpf_end = utrace_prof_end;
	}
}
