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

#ifndef	_UNITS_H
#define	_UNITS_H

#ifdef	__cplusplus
extern "C" {
#endif

#define	FP_SEC		1.0
#define	FP_MILLISEC	1000.0
#define	FP_MICROSEC	1000000.0
#define	FP_NANOSEC	1000000000.0

#define	U_SEC		1ULL
#define	U_MILLISEC	1000ULL
#define	U_MICROSEC	1000000ULL
#define	U_NANOSEC	1000000000ULL

#define	U_B		1UL
#define	U_KB		1024UL
#define	U_MB		1048576UL
#define	U_GB		1073741824UL
#define	U_TB		1099511627776ULL

#ifdef	__cplusplus
}
#endif

#endif	/* _UNITS_H */
