%{
/*********************************************************************
 *
 * Authors: Vincenzo Ciaschini - Vincenzo.Ciaschini@cnaf.infn.it 
 *
 * Copyright (c) Members of the EGEE Collaboration. 2004-2010.
 * See http://www.eu-egee.org/partners/ for details on the copyright holders.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
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
extern char *strndup(const char*, size_t);
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

<SINGLE_QUOTED>[^']*\' yytext[strlen(yytext)-1]='\0'; yylval_param->string = yytext; BEGIN(INITIAL); return SUBJECTS;

\" BEGIN(DOUBLE_QUOTED);
<DOUBLE_QUOTED>[^"]*\" yytext[strlen(yytext)-1]='\0'; yylval_param->string = yytext; BEGIN(INITIAL); return SUBJECTS;


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
                     
