%{
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
 * UTrace Lexer
 *
 * The following rules implement essentially a full C lexer, such that we can
 * easily extend the UTrace grammar later if that is required.  Since we do
 * not yet require type declarations, this file does not yet implement the
 * ident/type conflict resolution required for C, and the assignment of types
 * to integer constants using the [uU][lL] suffixes.
 */

#include <utrace_impl.h>
#include <ut_grammar.h>
#include <vmem.h>

typedef enum yytokentype yytokentype;
static int yycolumn;

static yytokentype ut_ldelim(YYLTYPE *, ut_pcb_t *, int *, yytokentype);
static yytokentype ut_rdelim(YYLTYPE *, ut_pcb_t *, int *, yytokentype);
static yytokentype ut_ident(YYLTYPE *, YYSTYPE *, ut_pcb_t *, const char *);
static yytokentype ut_int(YYLTYPE *, YYSTYPE *, ut_pcb_t *, const char *);
static yytokentype ut_float(YYLTYPE *, YYSTYPE *, ut_pcb_t *, const char *);
static yytokentype ut_str(YYLTYPE *, YYSTYPE *, ut_pcb_t *, char *);

static inline void
__attribute__((always_inline))
yysetloc(YYLTYPE *lp)
{
	lp->first_line = yylineno;
	lp->first_column = yycolumn;
	lp->last_line = yylineno;
	lp->last_column = yycolumn + yyleng - 1;
	yycolumn += yyleng;
}

static inline void
__attribute__((always_inline))
yynl(void)
{
	yycolumn = 1;
	yylineno++;
}

#define	YY_DECL \
    int yylex(YYSTYPE *yylval_param, YYLTYPE *yylloc_param, ut_pcb_t *pcb)

#define	YY_USER_ACTION	yysetloc(yylloc);
%}

%option	ansi-definitions
%option	ansi-prototypes

%option	bison-bridge
%option	bison-locations

%option noyyalloc
%option noyyrealloc
%option noyyfree

%s	S0 S1

RGX_IDENT	[a-zA-Z_][0-9a-zA-Z_]*
RGX_INT		([0-9]+|0[xX][0-9A-Fa-f]+)[uU]?[lL]?[lL]?
RGX_FLOAT	([0-9]+("."?)[0-9]*|"."[0-9]+)((e|E)("+"|-)?[0-9]+)?[fFlL]?
RGX_WS		[\f\r\t\v ]
RGX_STR		([^"\\\n]|\\[^"\n]|\\\")*
RGX_CHR		([^'\\\n]|\\[^'\n]|\\')*
RGX_CTL		^[\f\t\v ]*#

%%

<S0>"|"		return (UT_TOK_BOR);
<S0>"^"		return (UT_TOK_XOR);
<S0>"&"		return (UT_TOK_BAND);
<S0>"&&"	return (UT_TOK_LAND);
<S0>"^^"	return (UT_TOK_LXOR);
<S0>"||"	return (UT_TOK_LOR);
<S0>"=="	return (UT_TOK_EQU);
<S0>"!="	return (UT_TOK_NEQ);
<S0>"<"		return (UT_TOK_LT);
<S0>"<="	return (UT_TOK_LE);
<S0>">"		return (UT_TOK_GT);
<S0>">="	return (UT_TOK_GE);
<S0>"<<"	return (UT_TOK_LSH);
<S0>">>"	return (UT_TOK_RSH);
<S0>"+"		return (UT_TOK_ADD);
<S0>"-"		return (UT_TOK_SUB);
<S0>"*"		return (UT_TOK_MUL);
<S0>"/"		return (UT_TOK_DIV);
<S0>"%"		return (UT_TOK_MOD);
<S0>"~"		return (UT_TOK_BNEG);
<S0>"!"		return (UT_TOK_LNEG);
<S0>"?"		return (UT_TOK_QUESTION);
<S0>"."		return (UT_TOK_DOT);
<S0>"->"	return (UT_TOK_PTR);
<S0>"="		return (UT_TOK_ASGN);
<S0>"+="	return (UT_TOK_ADD_EQ);
<S0>"-="	return (UT_TOK_SUB_EQ);
<S0>"*="	return (UT_TOK_MUL_EQ);
<S0>"/="	return (UT_TOK_DIV_EQ);
<S0>"%="	return (UT_TOK_MOD_EQ);
<S0>"&="	return (UT_TOK_AND_EQ);
<S0>"^="	return (UT_TOK_XOR_EQ);
<S0>"|="	return (UT_TOK_OR_EQ);
<S0>"<<="	return (UT_TOK_LSH_EQ);
<S0>">>="	return (UT_TOK_RSH_EQ);
<S0>"++"	return (UT_TOK_ADDADD);
<S0>"--"	return (UT_TOK_SUBSUB);
<S0>"..."	return (UT_TOK_ELLIPSIS);
<S0><<EOF>>	return (UT_TOK_EOF);

<S0>"("		return (ut_ldelim(yylloc, pcb, &pcb->pcb_parens, UT_TOK_LPAR));
<S0>")"		return (ut_rdelim(yylloc, pcb, &pcb->pcb_parens, UT_TOK_RPAR));

<S0>"["		return (ut_ldelim(yylloc, pcb, &pcb->pcb_bracks, UT_TOK_LBRAC));
<S0>"]"		return (ut_rdelim(yylloc, pcb, &pcb->pcb_bracks, UT_TOK_RBRAC));

<S0>"{"		return (ut_ldelim(yylloc, pcb, &pcb->pcb_braces, '{'));
<S0>"}"		return (ut_rdelim(yylloc, pcb, &pcb->pcb_braces, '}'));

<S0>":"		return (':');
<S0>","		return (',');
<S0>";"		return (';');

<S0>__attribute__ return (UT_KEY___ATTRIBUTE__);
<S0>__thread	return (UT_KEY___THREAD);

<S0>auto	return (UT_KEY_AUTO);
<S0>break	return (UT_KEY_BREAK);
<S0>case	return (UT_KEY_CASE);
<S0>char	return (UT_KEY_CHAR);
<S0>const	return (UT_KEY_CONST);
<S0>continue	return (UT_KEY_CONTINUE);
<S0>default	return (UT_KEY_DEFAULT);
<S0>do		return (UT_KEY_DO);
<S0>double	return (UT_KEY_DOUBLE);
<S0>else	return (UT_KEY_ELSE);
<S0>enum	return (UT_KEY_ENUM);
<S0>extern	return (UT_KEY_EXTERN);
<S0>float	return (UT_KEY_FLOAT);
<S0>for		return (UT_KEY_FOR);
<S0>goto	return (UT_KEY_GOTO);
<S0>if		return (UT_KEY_IF);
<S0>int		return (UT_KEY_INT);
<S0>long	return (UT_KEY_LONG);
<S0>offsetof	return (UT_KEY_OFFSETOF);
<S0>on		return (UT_KEY_ON);
<S0>register	return (UT_KEY_REGISTER);
<S0>restrict	return (UT_KEY_RESTRICT);
<S0>return	return (UT_KEY_RETURN);
<S0>short	return (UT_KEY_SHORT);
<S0>signed	return (UT_KEY_SIGNED);
<S0>sizeof	return (UT_KEY_SIZEOF);
<S0>static	return (UT_KEY_STATIC);
<S0>struct	return (UT_KEY_STRUCT);
<S0>switch	return (UT_KEY_SWITCH);
<S0>typedef	return (UT_KEY_TYPEDEF);
<S0>typeof	return (UT_KEY_TYPEOF);
<S0>union	return (UT_KEY_UNION);
<S0>unsigned	return (UT_KEY_UNSIGNED);
<S0>void	return (UT_KEY_VOID);
<S0>volatile	return (UT_KEY_VOLATILE);
<S0>while	return (UT_KEY_WHILE);
<S0>with	return (UT_KEY_WITH);

<S0>{RGX_IDENT}	return (ut_ident(yylloc, yylval, pcb, yytext));
<S0>{RGX_INT}	return (ut_int(yylloc, yylval, pcb, yytext));
<S0>{RGX_FLOAT}	return (ut_float(yylloc, yylval, pcb, yytext));

<S0>\"{RGX_STR}$ yyuterror(yylloc, pcb, "newline encountered inside a string");
<S0>\"{RGX_STR}\" return (ut_str(yylloc, yylval, pcb, yytext));

<S0>{RGX_WS}	; /* discard */
<S0>"\\"\n	yynl(); /* discard */
<S0>\n		yynl(); /* discard */
<S0>.		yyuterror(yylloc, pcb, "syntax error");

<S0>"/*"	{
			pcb->pcb_cstate = (YYSTATE);
			BEGIN(S1);
		}

<S1>"/*"	yyuterror(yylloc, pcb, "/* encountered inside a comment");
<S1>"*/"	BEGIN(pcb->pcb_cstate);
<S1>.		; /* discard */
<S1>\n		yynl(); /* discard */

<S1><<EOF>>	{
			yyuterror(yylloc, pcb,
			    "end-of-file encountered before matching */");
			return (UT_TOK_EOF);
		}

%%

static yytokentype
ut_ldelim(YYLTYPE *lp, ut_pcb_t *pcb, int *cp, yytokentype tok)
{
	if (++(*cp) <= 0)
		yyuterror(lp, pcb, "%s overflow in input\n", ut_token_names[tok]);
	return (tok);
}

static yytokentype
ut_rdelim(YYLTYPE *lp, ut_pcb_t *pcb, int *cp, yytokentype tok)
{
	if (--(*cp) < 0)
		yyuterror(lp, pcb, "extra %s in input\n", ut_token_names[tok]);
	return (tok);
}

static yytokentype
ut_ident(YYLTYPE *lp, YYSTYPE *rp, ut_pcb_t *pcb, const char *s)
{
	rp->l_str = utrace_pcb_string(pcb, s);
	return (UT_TOK_IDENT);
}

static yytokentype
ut_int(YYLTYPE *lp, YYSTYPE *rp, ut_pcb_t *pcb, const char *s)
{
	char *e;

	errno = 0;
	rp->l_int = strtoull(s, &e, 0);

	if (e == s)
		yyuterror(lp, pcb, "invalid integer: %s", s);
	else if (errno == ERANGE)
		yyuterror(lp, pcb, "invalid integer: %s: overflow detected", s);
	else if (*e != '\0' && strchr("uUlL", *e) == NULL)
		yyuterror(lp, pcb, "invalid integer: %s", s);

	return (UT_TOK_INT);
	
}

static yytokentype
ut_float(YYLTYPE *lp, YYSTYPE *rp, ut_pcb_t *pcb, const char *s)
{
	char *e;

	errno = 0;
	rp->l_float = strtold(s, &e);

	if (e == s || *e != '\0')
		yyuterror(lp, pcb, "invalid float: %s", s);
	else if (errno == ERANGE)
		yyuterror(lp, pcb, "invalid float: %s: overflow detected", s);

	return (UT_TOK_FLOAT);
}

static yytokentype
ut_str(YYLTYPE *lp, YYSTYPE *rp, ut_pcb_t *pcb, char *s)
{
	s[yyleng - 1] = '\0';
	rp->l_str = utrace_pcb_string(pcb, s + 1);
	return (UT_TOK_STRING);
}

void
__attribute__((format(printf, 3, 4)))
yyuterror(YYLTYPE *lp, ut_pcb_t *pcb, const char *format, ...)
{
	va_list ap;

	if (lp->first_line == lp->last_line &&
	    lp->first_column == lp->last_column) {
		(void) fprintf(stderr, "line %d:%d: ",
		    lp->first_line, lp->first_column);
	} else if (lp->first_line == lp->last_line) {
		(void) fprintf(stderr, "line %d:%d-%d: ",
		    lp->first_line, lp->first_column, lp->last_column);
	} else {
		(void) fprintf(stderr, "lines %d-%d: ",
		    lp->first_line, lp->last_line);
	}

	va_start(ap, format);
	(void) vfprintf(stderr, format, ap);
	va_end(ap);
	(void) fprintf(stderr, "\n");

	pcb->pcb_errs++;
}

void
yyutinit(ut_pcb_t *pcb)
{
	yyutdebug = pcb->pcb_hdl->uth_dbg;
	yyin = pcb->pcb_stdin;

	yypush_buffer_state(yy_create_buffer(yyin, YY_BUF_SIZE));

	yylineno = 1;
	yycolumn = 1;

	BEGIN(S0);
}

void
yyutfini(ut_pcb_t *pcb)
{
	yypop_buffer_state();

	yylineno = 0;
	yycolumn = 0;
	yyutdebug = 0;
}

int
yywrap(void)
{
	return (1);
}

void *
yyalloc(size_t bytes)
{
	return (vmem_libc_malloc(bytes));
}

void *
yyrealloc(void *ptr, size_t bytes)
{
	return (vmem_libc_realloc(ptr, bytes));
}

void
yyfree(void *ptr)
{
	vmem_libc_free(ptr);
}
