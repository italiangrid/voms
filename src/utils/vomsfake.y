%{
#include "config.h"
#include <stdlib.h>
#include <string.h>

#include "parsertypes.h"

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
  else if (strcmp(param->name, "-target") == 0) {
    {
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
  }
  else if (strcmp(param->name, "-uri") == 0) {
    vo->uri = strdup(param->value);
  }
  else if (strcmp(param->name, "-ga") == 0) {
    vo->gas[vo->gasize++] = strdup(param->value);
    vo->gas[vo->gasize] = NULL;
  }
}
