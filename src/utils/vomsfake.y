%{
/*
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
 */
#include <stdlib.h>
#include <string.h>

#include "fakeparsertypes.h"
#include "lexparse.h"

#define MAX_SIZE 200

extern VOLIST* volist;
static void convertparam(VO *vo, PARAM* param);
%}

%error-verbose

%union{
  char *string;
  char *input;
  PARAM *param;
  PARAMLIST *params;
  VO *vo;
  VOLIST *vos;
}

%token <string> STRING
%token <string> ID;

%type <input> value;
%type <param> voparam
%type <params> voparams
%type <vo> vo
%type <vos> text

%%

text: vo {
  $$ = (VOLIST*)malloc(sizeof(VOLIST));
  $$->vos= (VO**)malloc(sizeof(VO*)*MAX_SIZE);
  $$->current=0;
  $$->vos[$$->current++] = $1;
  volist = $$;
 }
| text vo {
  $$ = $1;
  $$->vos[$$->current++] = $2;
  volist = $$;
 }
;

vo: '[' ID ']' voparams {
  $$ = (VO *)calloc(1,sizeof(VO));
  $$->fqans = (char**)malloc(sizeof(char*)*MAX_SIZE);
  $$->fqansize = 0;
  $$->gas = (char**)malloc(sizeof(char*)*MAX_SIZE);
  $$->gasize = 0;
  $$->targets = NULL;
  $$->voname = $2;
  $$->extensions = (char**)malloc(sizeof(char*)*MAX_SIZE);
  $$->extsize = 0;
  $$->params = $4;
  {
    int i =0;
    for (i = 0 ; i < $$->params->current; i++)
      convertparam($$, $$->params->params[i]);
  }
 }
| '[' ID ']' {
  $$ = (VO *)calloc(1,sizeof(VO));
  $$->fqans = NULL;
  $$->fqansize = 0;
  $$->gas = NULL;
  $$->gasize = 0;
  $$->targets = NULL;
  $$->voname = $2;
  $$->extensions = NULL;
  $$->extsize = 0;
  $$->params = NULL;

  }
;

voparams: voparam {
  $$ = (PARAMLIST *)malloc(sizeof(PARAMLIST));
  $$->params = (PARAM**)malloc(sizeof(PARAM*)*MAX_SIZE);
  $$->current=0;
  $$->params[$$->current++] = $1;
 }
| voparams voparam {
  $$ = $1;
  $$->params[$$->current++] = $2;  
 }
;

voparam: ID '=' value {
  $$ = (PARAM *)calloc(1,sizeof(PARAM));
  $$->name = $1;
  $$->value = $3;
 }
| ID '=' value '=' value {
  $$ = (PARAM *)calloc(1,sizeof(PARAM));
  $$->name = $1;
  $$->value = malloc(strlen($3)+strlen($5)+4);
  strcpy($$->value, "::");
  strcat($$->value, $3);
  strcat($$->value,"=");
  strcat($$->value, $5);
  free($3);
  free($5);
 }
| ID '=' value '=' value '(' value ')' {
  $$ = (PARAM *)calloc(1,sizeof(PARAM));
  $$->name = $1;
  $$->value = malloc(strlen($3)+strlen($5)+strlen($7)+4);
  strcpy($$->value, $7);
  strcat($$->value, "::");
  strcat($$->value, $3);
  strcat($$->value,"=");
  strcat($$->value, $5);
  free($3);
  free($5);
  free($7);
 }
;

value: ID { $$ = $1; }
    |  STRING { $$ = $1; }
;

%%

static void convertparam(VO *vo, PARAM* param)
{
  if (strcmp(param->name, "-hostcert") == 0) {
    vo->hostcert = strdup(param->value);
  }
  else if (strcmp(param->name,"-hostkey") == 0) {
    vo->hostkey = strdup(param->value);
  }
  else if (strcmp(param->name, "-fqan") == 0) {
    vo->fqans[vo->fqansize++] = strdup(param->value);
  }
  else if (strcmp(param->name, "-vomslife") == 0) {
    vo->vomslife = atoi(param->value)*3600;
  }
  else if (strcmp(param->name, "-pastac") == 0) {
    vo->pastac = strdup(param->value);
  }
  else if (strcmp(param->name, "-target") == 0) {
    int do_add = 1;

    if (vo->targets == NULL) {
      do_add = 0;
      vo->targets = malloc(1);
      vo->targets[0] = '\0';
    }
    vo->targets = realloc(vo->targets, strlen(vo->targets) +
                          strlen(param->value) + 4);
    if (do_add)
      vo->targets = strcat(vo->targets, ",");
    vo->targets = strcat(vo->targets, param->value);
  }
  else if (strcmp(param->name, "-uri") == 0) {
    vo->uri = strdup(param->value);
  }
  else if (strcmp(param->name, "-ga") == 0) {
    vo->gas[vo->gasize++] = strdup(param->value);
    vo->gas[vo->gasize] = NULL;
  }
  else if (strcmp(param->name, "-acextension") == 0) {
    vo->extensions[vo->extsize++] = strdup(param->value);
  }
  free(param->value);
  free(param->name);
}
