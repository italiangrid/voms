%{
/*********************************************************************
 *
 * Authors: Vincenzo Ciaschini - Vincenzo.Ciaschini@cnaf.infn.it 
 *          Valerio Venturi    - Valerio.Venturi@cnaf.infn.it
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
#include <ctype.h>

#include "parsertypes.h"
#include "listfunc.h"

char **parse_subjects(char *string);
void signingerror(void *policies, void *scanner, char const *msg);
%}

%error-verbose
%pure-parser
%name-prefix="signing"
%parse-param {struct policy ***policies}
%parse-param {void *scanner}
%lex-param {void *scanner}

%union{
  char *string;
  struct condition *cond;
  struct policy *policy;
  void *array;
}

%token <string> SUBJECTS
%token COND_SUBJECTS
%token COND_BANNED          
%token GLOBUS               
%token POS_RIGHTS           
%token NEG_RIGHTS           
%token CA_SIGN              
%token ACCESS_ID_CA 
%token ACCESS_ID_ANYBODY
%token X509

%type <policy>    eacl_entry
%type <policy>    access_identity
%type <cond>      realcondition
%type <array>     restrictions
%type <policy>    access_identities
%%

eacl: eacl_entry      { *policies = (struct policy **)listadd((char**)(*policies), (char*)($1)); }
| eacl eacl_entry { *policies = (struct policy **)listadd((char**)(*policies), (char*)($2)); }

eacl_entry: access_identities POS_RIGHTS GLOBUS CA_SIGN restrictions {
  if ($1) {
    $$->conds = (struct condition**)($5);
  }
  $$ = $1;
}
| access_identities NEG_RIGHTS GLOBUS CA_SIGN restrictions {
  /* Ignore this.  Globus does. */
  free($1);
  $$ = NULL;
}

access_identities: access_identity {
  $$ = $1;
}

restrictions: realcondition {
  $$ = listadd(NULL, (char*)($1));
}
| realcondition restrictions {
  $$ = listadd($2, (char*)($1));
}


access_identity: ACCESS_ID_CA X509 SUBJECTS {
  $$ = (struct policy *)calloc(1, sizeof(struct policy));

  if ($$) {
    char **subjects = parse_subjects($3);
    $$->caname = strdup(subjects[0]);
    free(subjects);
    $$->type = TYPE_SIGNING;
  }

  if ($$ && !$$->caname) {
    free($$);
    $$ = NULL;
  }
}
| ACCESS_ID_ANYBODY {
  $$ = (struct policy *)calloc(1, sizeof(struct policy));
}

realcondition: COND_SUBJECTS GLOBUS SUBJECTS { 
    $$ = (struct condition*)malloc(sizeof(struct condition));
    if ($$) {
      $$->positive = 1;
      $$->original = strdup($3);
      $$->subjects = parse_subjects($$->original);
      if (!$$->subjects) {
        free($$->original);
        free($$);
        $$ = NULL;
      }
    }
}
| COND_BANNED GLOBUS SUBJECTS {
    $$ = (struct condition*)malloc(sizeof(struct condition));

    if ($$) {
      $$->positive = 0;
      $$->original = strdup($3);
      $$->subjects = parse_subjects($$->original);
      if (!$$->subjects) {
        free($$->original);
        free($$);
        $$ = NULL;
      }
    }
}
;

%%

char **parse_subjects(char *string)
{
  char **list = NULL;
  char divider;

  if (!string)
    return NULL;

  do {
    divider = string[0];

    if (divider == '\'' || divider == '"') {
      char *end = strchr(string + 1, divider);
      if (!end)
        return list;
      *end = '\0';

      list = (char**)listadd(list, string+1);
      string = ++end;
      while (isspace(*string))
        string++;
    }
    else if (divider == '\0')
      break;
    else  {
      list = (char**)listadd(list, string);
      string += strlen(string);
    }
  } while (string && string[0] != '\0');

  return list;
}

#if 0
int main()
{
  signingdebug = 1;
  void **arg = NULL;
  void *scanner=NULL;
  signinglex_init(&scanner);
  signingset_debug(1, scanner);
  return signingparse(arg, scanner);
}
#endif
void signingerror(UNUSED(void *policies), UNUSED(void *scanner), UNUSED(char const *msg))
{
}
