%{
/*********************************************************************
 *
 * Authors: Vincenzo Ciaschini - Vincenzo.Ciaschini@cnaf.infn.it 
 *
 * Copyright (c) 2002-2009 INFN-CNAF on behalf of the EU DataGrid
 * and EGEE I, II and III
 * For license conditions see LICENSE file or
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 *
 * Parts of this code may be based upon or even include verbatim pieces,
 * originally written by other people, in which case the original header
 * follows.
 *
 *********************************************************************/
#include "config.h"
#include <stdio.h>
#include <string.h>

#include <stdlib.h>

#include "parsertypes.h"
#include "namespaces.h"
extern char *strndup(char*, size_t);
%}

%x SINGLE_QUOTED
%x DOUBLE_QUOTED

%option reentrant
%option noyywrap
%option prefix="namespaces"
%option bison-bridge

%%

\#.*  /* comment. Ignore */

\' BEGIN(SINGLE_QUOTED);

<SINGLE_QUOTED>.*\' yylval_param->string = yytext; BEGIN(INITIAL); return SUBJECT;

\" BEGIN(DOUBLE_QUOTED);
<DOUBLE_QUOTED>.*\" yylval_param->string = yytext; BEGIN(INITIAL); return SUBJECT;


(?i:TO)       return TO;
(?i:ISSUER)   return ISSUER;
(?i:PERMIT)   return PERMIT;
(?i:DENY)     return DENY;
(?i:SELF)     return SELF;
(?i:SUBJECT)  return SUBJECT_WORD;
\\$
\n
.

%%
