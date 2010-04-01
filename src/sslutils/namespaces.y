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

char **nmlistadd(char **vect, char *data, int size);
char **parse_subjects(char *string);
void namespaceserror(void *policies, void *scanner, char const *msg);
%}

%error-verbose
%pure-parser
%name-prefix="namespaces"
%parse-param {struct policy ***policies}
%parse-param {void *scanner}
%lex-param   {void *scanner}

%union{
  char *string;
  struct condition *cond;
  struct policy *policy;
  int integer;
}

%token <string> SUBJECT
%token TO
%token SELF
%token PERMIT
%token DENY
%token SUBJECT_WORD
%token ISSUER

%type <policy>  rule
%type <cond>    condition
%type <integer> permit_or_deny

%%

eacl: rule  { *policies = (struct policy**)nmlistadd((char**)*policies, (char*)($1), sizeof($1)); }
| eacl rule { *policies = (struct policy**)nmlistadd((char**)*policies, (char*)($2), sizeof($2)); }
;

rule: TO ISSUER SUBJECT condition {
  $$ = (struct policy *)calloc(1, sizeof(struct policy));
  if ($$) {
    $$->self = 0;
    $$->caname = strdup($3);
    $$->conds = (struct condition**)nmlistadd(NULL, (char*)($4), sizeof(struct condition *));
    $$->type = TYPE_NAMESPACE;
  }

 }
| TO ISSUER SELF condition {
  $$ = (struct policy *)calloc(1, sizeof(struct policy));
  if ($$) {
    $$->self = 1;
    $$->caname = NULL;
    $$->conds = (struct condition**)nmlistadd(NULL, (char*)($4), sizeof(struct condition *));
    $$->type = TYPE_NAMESPACE;
  }
 }
;

condition: permit_or_deny SUBJECT_WORD SUBJECT {
  $$ = (struct condition *)calloc(1, sizeof(struct condition));
  if ($$) {
    $$->positive = $1;
    $$->original = strdup($3);
    $$->subjects = nmlistadd(NULL, $$->original, sizeof(char*));
    if (!$$->subjects) {
      free($$->original);
      free($$);
        $$ = NULL;
    }
  }
}
;

permit_or_deny: PERMIT { $$ = 1; }
| DENY { $$ = 0; }
;

%%

char **nmlistadd(char **vect, char *data, int size)
{
  int i = 0;
  char **newvect;

  if (!data || (size <= 0))
    return NULL;

  if (vect)
    while (vect[i++]) ;
  else
    i=1;

  if ((newvect = (char **)malloc((i+1)*size))) {
    if (vect) {
      memcpy(newvect, vect, (size*(i-1)));
      newvect[i-1] = data;
      newvect[i] = NULL;
      free(vect);
    }
    else {
      newvect[0] = data;
      newvect[1] = NULL;
    }
    return newvect;
  }
  return NULL;
}

#if 0
int main()
{
  namespacesdebug = 1;
  void **arg = NULL;
  void *scanner=NULL;
  namespaceslex_init(&scanner);
  namespacesset_debug(1, scanner);
  return namespacesparse(arg, scanner);
}
#endif

void namespaceserror(UNUSED(void *policies), UNUSED(void *scanner), UNUSED(char const *msg))
{
}
