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

#ifndef	_UT_PARSER_H
#define	_UT_PARSER_H

#ifdef	__cplusplus
extern "C" {
#endif

#define	UT_TYPE_VOID	0x000	/* base: void */
#define	UT_TYPE_INT	0x001	/* base: int */
#define	UT_TYPE_CHAR	0x002	/* base: char */
#define	UT_TYPE_WCHAR	0x003	/* base: wchar */
#define	UT_TYPE_STRING	0x004	/* base: string */
#define	UT_TYPE_WSTRING	0x005	/* base: wstring */
#define	UT_TYPE_FLOAT	0x006	/* base: float */
#define	UT_TYPE_STRUCT	0x007	/* base: struct */
#define	UT_TYPE_UNION	0x008	/* base: union */
#define	UT_TYPE_FUNC	0x009	/* base: function */

#define	UT_TYPE_UNSIGN	0x010	/* flag: unsigned int or char */
#define	UT_TYPE_LONG	0x020	/* flag: long int or double */
#define	UT_TYPE_LLONG	0x040	/* flag: long long or long double */
#define	UT_TYPE_SHORT	0x080	/* flag: short int */
#define	UT_TYPE_PTR	0x100	/* flag: pointer to type */
#define	UT_TYPE_ARRAY	0x200	/* flag: array of type */

#define	UT_TYPE_BASE(t)	((t) & 0x00F)
#define	UT_TYPE_FLAG(t)	((t) & 0xFF0)

#define	UT_TYPE_UINT32	(UT_TYPE_INT | UT_TYPE_UNSIGN)
#define	UT_TYPE_UINT64	(UT_TYPE_INT | UT_TYPE_UNSIGN | UT_TYPE_LLONG)
#define	UT_TYPE_UINTPTR	(UT_TYPE_INT | UT_TYPE_UNSIGN | UT_TYPE_LONG)

struct ut_pcb;
struct ut_str;

typedef struct ut_node {
	enum yytokentype node_token;
	uint16_t node_type;
	YYLTYPE node_loc;
	YYSTYPE node_value;
	struct ut_node *node_lhs;
	struct ut_node *node_rhs;
	struct ut_node *node_list;
	struct ut_node *node_link;
} ut_node_t;

extern ut_node_t *utrace_node_link(ut_node_t *, ut_node_t *);
extern ut_node_t *utrace_node_ident(const YYLTYPE *, struct ut_pcb *,
    const struct ut_str *);
extern ut_node_t *utrace_node_int(const YYLTYPE *, struct ut_pcb *,
    unsigned long long);
extern ut_node_t *utrace_node_float(const YYLTYPE *, struct ut_pcb *,
    long double);
extern ut_node_t *utrace_node_string(const YYLTYPE *, struct ut_pcb *,
    const struct ut_str *);
extern ut_node_t *utrace_node_params(const YYLTYPE *, struct ut_pcb *,
    const struct ut_str *, ut_node_t *);
extern ut_node_t *utrace_node_op2(const YYLTYPE *, struct ut_pcb *,
    enum yytokentype, ut_node_t *, ut_node_t *);

typedef void ut_node_f(struct ut_pcb *, ut_node_t *, void *);
extern int utrace_node_walk(struct ut_pcb *, ut_node_t *, ut_node_f *, void *);

extern void yyuterror(YYLTYPE *, struct ut_pcb *, const char *, ...)
    __attribute__((format(printf, 3, 4)));

extern int yyutlex_destroy(void);
extern int yyutlex(YYSTYPE *, YYLTYPE *, struct ut_pcb *);
extern int yyutparse(struct ut_pcb *);

extern void yyutinit(struct ut_pcb *);
extern void yyutfini(struct ut_pcb *);

extern const char *const *ut_token_names;
extern int yyutdebug;

#ifdef	__cplusplus
}
#endif

#endif	/* _UT_PARSER_H */
