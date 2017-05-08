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
 * UTrace GLR Grammar
 *
 * At present, this is very simple, but we define all of the C operators and
 * keywords as a placeholder for potential future expansion.  The rules here
 * simply compose a parse tree by calling the ut_parser.c node constructors,
 * and then returning the resulting tree root back from yyparse() in the pcb.
 *
 * Example syntax:
 *
 * on event:"something"
 * {
 *   trace(errno);
 * } 
 *
 * on file:"a.c", line:123
 * {
 *   print(args);
 * }
 */

#include <utrace_impl.h>
#include <vmem.h>

#define	YYMALLOC	vmem_libc_malloc
#define	YYREALLOC	vmem_libc_realloc
#define	YYFREE		vmem_libc_free
%}

%debug
%define api.pure
%glr-parser
%locations
%token-table

%code requires {
	struct ut_pcb;
}

%lex-param{struct ut_pcb *pcb}
%parse-param{struct ut_pcb *pcb}

%union {
	int l_tok;
	const struct ut_str *l_str;
	unsigned long long l_int;
	long double l_float;
	struct ut_node *l_node;
}

%token	<l_tok>	UT_TOK_ADD	"+"
%token	<l_tok>	UT_TOK_ADDADD	"++"
%token	<l_tok>	UT_TOK_ADDROF	"&( )"
%token	<l_tok>	UT_TOK_ADD_EQ	"+="
%token	<l_tok>	UT_TOK_AND_EQ	"&="
%token	<l_tok>	UT_TOK_ASGN	"="
%token	<l_tok>	UT_TOK_BAND	"&"
%token	<l_tok>	UT_TOK_BNEG	"~"
%token	<l_tok>	UT_TOK_BOR	"|"
%token	<l_tok>	UT_TOK_DEREF	"*( )"
%token	<l_tok>	UT_TOK_DIV	"/"
%token	<l_tok>	UT_TOK_DIV_EQ	"/="
%token	<l_tok>	UT_TOK_DOT	"."
%token	<l_tok> UT_TOK_ELLIPSIS	"..."
%token	<l_tok>	UT_TOK_EQU	"=="
%token	<l_tok>	UT_TOK_GE	">="
%token	<l_tok>	UT_TOK_GT	">"
%token	<l_tok>	UT_TOK_INEG	"-<int>"
%token	<l_tok>	UT_TOK_IPOS	"+<int>"
%token	<l_tok>	UT_TOK_LAND	"&&"
%token	<l_tok>	UT_TOK_LBRAC	"["
%token	<l_tok>	UT_TOK_LE	"<="
%token	<l_tok>	UT_TOK_LNEG	"!"
%token	<l_tok>	UT_TOK_LOR	"||"
%token	<l_tok>	UT_TOK_LPAR	"("
%token	<l_tok>	UT_TOK_LSH	"<<"
%token	<l_tok>	UT_TOK_LSH_EQ	"<<="
%token	<l_tok>	UT_TOK_LT	"<"
%token	<l_tok>	UT_TOK_LXOR	"^^"
%token	<l_tok>	UT_TOK_MOD	"%"
%token	<l_tok>	UT_TOK_MOD_EQ	"%="
%token	<l_tok>	UT_TOK_MUL	"*"
%token	<l_tok>	UT_TOK_MUL_EQ	"*="
%token	<l_tok>	UT_TOK_NEQ	"!="
%token	<l_tok>	UT_TOK_OR_EQ	"|="
%token	<l_tok>	UT_TOK_POSTDEC	"( )--"
%token	<l_tok>	UT_TOK_POSTINC	"( )++"
%token	<l_tok>	UT_TOK_PREDEC	"--( )"
%token	<l_tok>	UT_TOK_PREINC	"++( )"
%token	<l_tok>	UT_TOK_PTR	"->"
%token	<l_tok>	UT_TOK_QUESTION	"?"
%token	<l_tok>	UT_TOK_RBRAC	"]"
%token	<l_tok>	UT_TOK_RPAR	")"
%token	<l_tok>	UT_TOK_RSH	">>"
%token	<l_tok>	UT_TOK_RSH_EQ	">>="
%token	<l_tok>	UT_TOK_SUB	"-"
%token	<l_tok>	UT_TOK_SUBSUB	"--"
%token	<l_tok>	UT_TOK_SUB_EQ	"-="
%token	<l_tok>	UT_TOK_XOR	"^"
%token	<l_tok>	UT_TOK_XOR_EQ	"^="

%token	<l_str>	UT_TOK_IDENT	"<ident>"
%token	<l_int>	UT_TOK_INT	"<int>"
%token	<l_float> UT_TOK_FLOAT	"<float>"
%token	<l_str>	UT_TOK_STRING	"<string>"

%token	UT_TOK_MAX
%token	UT_TOK_EOF 0	"end-of-file"

%token	UT_KEY___ATTRIBUTE__	"__attribute__"
%token	UT_KEY___THREAD		"__thread"
%token	UT_KEY_AUTO		"auto"
%token	UT_KEY_BREAK		"break"
%token	UT_KEY_CASE		"case"
%token	UT_KEY_CHAR		"char"
%token	UT_KEY_CONST		"const"
%token	UT_KEY_CONTINUE		"continue"
%token	UT_KEY_DEFAULT		"default"
%token	UT_KEY_DO		"do"
%token	UT_KEY_DOUBLE		"double"
%token	UT_KEY_ELSE		"else"
%token	UT_KEY_ENUM		"enum"
%token	UT_KEY_EXTERN		"extern"
%token	UT_KEY_FLOAT		"float"
%token	UT_KEY_FOR		"for"
%token	UT_KEY_GOTO		"goto"
%token	UT_KEY_IF		"if"
%token	UT_KEY_INT		"int"
%token	UT_KEY_LONG		"long"
%token	UT_KEY_OFFSETOF		"offsetof"
%token	UT_KEY_ON		"on"
%token	UT_KEY_REGISTER		"register"
%token	UT_KEY_RESTRICT		"restrict"
%token	UT_KEY_RETURN		"return"
%token	UT_KEY_SHORT		"short"
%token	UT_KEY_SIGNED		"signed"
%token	UT_KEY_SIZEOF		"sizeof"
%token	UT_KEY_STATIC		"static"
%token	UT_KEY_STRUCT		"struct"
%token	UT_KEY_SWITCH		"switch"
%token	UT_KEY_TYPEDEF		"typedef"
%token	UT_KEY_TYPEOF		"typeof"
%token	UT_KEY_UNION		"union"
%token	UT_KEY_UNSIGNED		"unsigned"
%token	UT_KEY_VOID		"void"
%token	UT_KEY_VOLATILE		"volatile"
%token	UT_KEY_WHILE		"while"
%token	UT_KEY_WITH		"with"

%token	UT_KEY_MAX

%left	','
%right	UT_TOK_ASGN UT_TOK_ADD_EQ UT_TOK_SUB_EQ UT_TOK_MUL_EQ UT_TOK_DIV_EQ
	UT_TOK_MOD_EQ UT_TOK_AND_EQ UT_TOK_XOR_EQ UT_TOK_OR_EQ UT_TOK_LSH_EQ
%left	UT_TOK_QUESTION ':'
%left	UT_TOK_LOR
%left	UT_TOK_LXOR
%left	UT_TOK_LAND
%left	UT_TOK_BOR
%left	UT_TOK_XOR
%left	UT_TOK_BAND
%left	UT_TOK_EQU UT_TOK_NEQ
%left	UT_TOK_LT UT_TOK_LE UT_TOK_GT UT_TOK_GE
%left	UT_TOK_LSH UT_TOK_RSH
%left	UT_TOK_ADD UT_TOK_SUB
%left	UT_TOK_MUL UT_TOK_DIV UT_TOK_MOD
%right	UT_TOK_LNEG UT_TOK_BNEG UT_TOK_ADDADD UT_TOK_SUBSUB
	UT_TOK_IPOS UT_TOK_INEG
%right	UT_TOK_DEREF UT_TOK_ADDROF UT_TOK_SIZEOF UT_TOK_TYPEOF
%left	UT_TOK_LPAR UT_TOK_RPAR UT_TOK_LBRAC UT_TOK_RBRAC UT_TOK_PTR UT_TOK_DOT

%type	<l_node>	request
%type	<l_node>	request_list

%type	<l_node>	ext_decl
%type	<l_node>	probe

%type	<l_node>	statement
%type	<l_node>	compound_statement
%type	<l_node>	block_item_list
%type	<l_node>	block_item
%type	<l_node>	expression_statement
%type	<l_node>	expression

%type	<l_node>	arg_form_list
%type	<l_node>	arg_form
%type	<l_node> 	arg_expr_list
%type	<l_node> 	arg_expr

%%

request:	UT_TOK_EOF { $$ = pcb->pcb_root = NULL; }
	|	request_list UT_TOK_EOF { $$ = pcb->pcb_root = $1; }
	;

request_list:	ext_decl { $$ = $1; }
	|	request_list ext_decl { $$ = utrace_node_link($1, $2); }
	;

ext_decl:	probe { $$ = $1; }
	|	error ';' { yyerrok; $$ = NULL; }
	;

probe:		UT_KEY_ON arg_form_list compound_statement {
			$$ = utrace_node_op2(&@1, pcb, UT_KEY_ON, $2, $3);
		}
	|	UT_KEY_ON compound_statement {
			$$ = utrace_node_op2(&@1, pcb, UT_KEY_ON, NULL, $2);
		}
	;

statement:
		compound_statement { $$ = $1; }
	|	expression_statement { $$ = $1; }
	;

compound_statement:
		'{' '}' { $$ = NULL; }
	|	'{' block_item_list '}' { $$ = $2; }
	;

block_item_list:
		block_item { $$ = $1; }
	|	block_item_list block_item { $$ = utrace_node_link($1, $2); }
	;	

block_item:	statement { $$ = $1; }
	;

expression_statement:
		';' { $$ = NULL; }
	|	expression ';' { $$ = $1; }
	|	error ';' { yyerrok; $$ = NULL; }
	;

expression:	UT_TOK_IDENT UT_TOK_LPAR UT_TOK_RPAR {
			$$ = utrace_node_params(&@1, pcb, $1, NULL);
		}
	|	UT_TOK_IDENT UT_TOK_LPAR arg_expr_list UT_TOK_RPAR {
			$$ = utrace_node_params(&@1, pcb, $1, $3);
		}
	;

arg_form_list:	arg_form { $$ = $1; }
	|	arg_form_list ',' arg_form { $$ = utrace_node_link($1, $3); }
	;

arg_form:	UT_TOK_IDENT ':' arg_expr {
			$$ = utrace_node_params(&@1, pcb, $1, $3);
		}
	;


arg_expr_list:	arg_expr { $$ = $1; }
	|	arg_expr_list ',' arg_expr { $$ = utrace_node_link($1, $3); }
	;

arg_expr:	UT_TOK_IDENT { $$ = utrace_node_ident(&@1, pcb, $1); }
	|	UT_TOK_INT { $$ = utrace_node_int(&@1, pcb, $1); }
	|	UT_TOK_FLOAT { $$ = utrace_node_float(&@1, pcb, $1); }
	|	UT_TOK_STRING { $$ = utrace_node_string(&@1, pcb, $1); }
	;

%%

const char *const *ut_token_names = yytname;
