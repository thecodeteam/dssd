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

#ifndef _P2_H
#define	_P2_H

#ifndef __KERNEL__
#include <stdint.h>
#endif

#ifdef	__cplusplus
extern "C" {
#endif

#define	P2ALIGN(x, a)		((x) & -(__typeof__(x))(a))
#define	P2PHASE(x, a)		((x) & ((a) - 1))
#define	P2NPHASE(x, a)		(-(x) & ((a) - 1))
#define	P2ROUNDUP(x, a)		(-(-(x) & -(__typeof__(x))(a)))
#define	P2END(x, a)		(-(~(x) & -(__typeof__(x))(a)))
#define	P2PHASEUP(x, a, phase)	\
	((phase) - (((phase) - (x)) & -(__typeof__(x))(a)))
#define	P2BOUNDARY(off, len, a)	(((off) ^ ((off) + (len) - 1)) > (a) - 1)
#define	P2SAMEHIGHBIT(x, y)	(((x) ^ (y)) < ((x) & (y)))
#define	P2CLEARLOWBIT(x)	((x) & ((x) - 1))
#define	P2ALIGNOF(x)		((x) ^ ((x) & ((x) - 1)))

#define	IS_P2(x)		(P2CLEARLOWBIT(x) == 0)
#define	IS_P2ALIGNED(p, a)	((((uintptr_t)(p)) & ((uintptr_t)(a) - 1)) == 0)

#ifdef	__cplusplus
}
#endif

#endif	/* _P2_H */
