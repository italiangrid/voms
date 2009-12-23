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
#include "signing_policy.h"
extern char *strndup(char*, size_t);
%}

%x SINGLE_QUOTED
%x DOUBLE_QUOTED

%option reentrant
%option noyywrap
%option prefix="signing"
%option bison-bridge

%%

#.* /* ignore comments */
\' BEGIN(SINGLE_QUOTED);

<SINGLE_QUOTED>.*\' yylval_param->string = yytext; BEGIN(INITIAL); return SUBJECTS;

\" BEGIN(DOUBLE_QUOTED);
<DOUBLE_QUOTED>.*\" yylval_param->string = yytext; BEGIN(INITIAL); return SUBJECTS;


cond_subjects                   return COND_SUBJECTS;
cond_banned_subjects            return COND_BANNED;
globus                          return GLOBUS;
pos_rights                      return POS_RIGHTS;
neg_rights                      return NEG_RIGHTS;
CA\:sign                        return CA_SIGN;
access_id_CA                    return ACCESS_ID_CA;
access_id_ANYBODY               return ACCESS_ID_ANYBODY;    
X509                            return X509;

\n
.
                     
