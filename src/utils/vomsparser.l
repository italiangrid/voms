%{
/*********************************************************************
 *
 * Authors: Vincenzo Ciaschini - Vincenzo.Ciaschini@cnaf.infn.it 
 *          Valerio Venturi    - Valerio.Venturi@cnaf.infn.it
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
#include "vomsparser.h"
extern char* strdup(const char*); /* Local declaration to avoid spurious warning from gcc */
%}

%x STR
%option noyywrap

%%
\"       BEGIN(STR);

<STR>[^\"]*   yylval.string = strdup(yytext); return STRING;
<STR>\"  BEGIN(INITIAL);

[a-zA-Z0-9_\.\:\/\-]* yylval.string = strdup(yytext); return ID;

[^ \t\n]              return yytext[0];

\n
.

%%

void yyerror(char const *s)
{
    fprintf(stderr, "ERROR: %s\n",s);
}
