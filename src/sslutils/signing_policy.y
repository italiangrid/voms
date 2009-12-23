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
  //#include "listfunc.h"

#include "parsertypes.h"

char **splistadd(char **vect, char *data, int size);
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

eacl: eacl_entry      { *policies = splistadd(*policies, $1, sizeof($1)); }
| eacl eacl_entry { *policies = splistadd(*policies, $2, sizeof($2)); }

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
  $$ = splistadd(NULL, $1, sizeof($1));
}
| realcondition restrictions {
  $$ = splistadd($2, $1, sizeof($1));
}


access_identity: ACCESS_ID_CA X509 SUBJECTS {
  $$ = (struct policy *)calloc(1, sizeof(struct policy));

  if ($$) {
    char **subjects = parse_subjects($3);
    $$->caname = strdup(subjects[0]);
    free(subjects);
    $$->type = TYPE_SIGNING;
  }

  if (!$$->caname) {
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

char **splistadd(char **vect, char *data, int size)
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

char **parse_subjects(char *string)
{
  char *temp = NULL;
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

      list = (char**)splistadd(list, string+1, sizeof(char*));
      string = ++end;
      while (isspace(*string))
        string++;
    }
    else if (divider == '\0')
      break;
    else  {
      list = (char**)splistadd(list, string, sizeof(char*));
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
void signingerror(void *policies, void *scanner, char const *msg)
{
}
