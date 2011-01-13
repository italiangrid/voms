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
#include <openssl/x509.h>
#include "parsertypes.h"
#include "doio.h"
#include "listfunc.h"
#include "normalize.h"

#include <regex.h>
#include <stdio.h>
#include <string.h>

static char *gethash(X509 *cert, char *hash);
static int find_policy(struct policy **policies, X509 *cert, int current);
static int evaluate_match_namespace(char *pattern, char *subject, int type);
static int evaluate_match_signing(char *pattern, char *subject, int type);
static int restriction_evaluate_policy(X509 *cert, struct policy *policy);
static int evaluate_cert(X509 *cert, struct policy **namespaces);
static int restriction_evaluate_namespace(STACK_OF(X509) *chain, struct policy **namespaces);
static int restriction_evaluate_signing(STACK_OF(X509) *chain, struct policy **signings);
static FILE *open_from_dir(char *path, char *file);

extern int  signinglex_init (void** scanner);
extern void signingset_in  (FILE * in_str ,void *yyscanner );
extern int  signinglex_destroy (void* yyscanner );
extern int  signingparse(struct policy ***policies, void *scanner);

extern int  namespaceslex_init (void** scanner);
extern void namespacesset_in  (FILE * in_str ,void *yyscanner );
extern int  namespaceslex_destroy (void* yyscanner );
extern int  namespacesparse(struct policy ***policies, void *scanner);

static int find_policy(struct policy **policies, X509 *cert, int current)
{
  int i = (current == -1 ? 0 : current + 1);

  char hash[EVP_MAX_MD_SIZE+1];

  if (!policies || !(policies[0]) || !cert)
    return -1;
  
  while (policies[i]) {
    if (policies[i]->self) {
      if (!strcmp(gethash(cert, hash), policies[i]->caname))
        return i;
    }
    else {
      char *issuer = X509_NAME_oneline(X509_get_issuer_name(cert), NULL, 0);
      int ret = strcmp(issuer, policies[i]->caname);
      OPENSSL_free(issuer);

      if (!ret)
        return i;
    }
    i++;
  }

  /* If code reaches here, no match was found. */
  return -1;
}

static char *gethash(X509 *cert, char *hash)
{
  unsigned long hashvalue = X509_subject_name_hash(cert);
  sprintf(hash, "%08lx", hashvalue);
  return hash;
}

static int evaluate_match_namespace(char *pattern, char *subject, int type)
{
  regex_t compiled;
  regmatch_t match[1];
  int success = SUCCESS_UNDECIDED;
  char *patterntmp = normalize(pattern);
  char *subjecttmp = normalize(subject);

  if (!regcomp(&compiled, patterntmp, REG_NOSUB)) {
    if (!regexec(&compiled, subjecttmp, 0, match, 0)) {
      /* matched */
      if (type)
        success = SUCCESS_PERMIT;
      else
        success = SUCCESS_DENY;
    }
  }

  regfree(&compiled);
  free(patterntmp);
  free(subjecttmp);

  return success;
}

static int evaluate_match_signing(char *pattern, char *subject, int type)
{
  int success = SUCCESS_UNDECIDED;
  int len = 0;
  int compare;
  char *patterntmp = normalize(pattern);
  char *subjecttmp = normalize(subject);

  if (!pattern || !subject)
    return success;

  len = strlen(pattern);

  if (pattern[len-1] == '*')
    compare = strncmp(patterntmp, subjecttmp, len-1);
  else
    compare = strcmp(patterntmp, subjecttmp);

  free(patterntmp);
  free(subjecttmp);

  if (!compare) {
    if (type) 
      return SUCCESS_PERMIT;
    else
      return SUCCESS_DENY;
  }

  return success;
}

static int restriction_evaluate_policy(X509 *cert, struct policy *policy)
{
  int success = SUCCESS_UNDECIDED;
  char *subject = NULL;

  struct condition **cond = NULL;
  int condindex = 0;
  int subjindex = 0;

  if (!policy || !cert || !policy->conds)
    return success;

  subject = X509_NAME_oneline(X509_get_subject_name(cert), 0 ,0);
  if (!subject)
    return success;

  cond = policy->conds;

  while (cond[condindex]) {
    if (cond[condindex]->subjects) {
      char **subjects = cond[condindex]->subjects;
      int tempsuccess;

      while (subjects[subjindex]) {
        if (policy->type == TYPE_NAMESPACE)
          tempsuccess = evaluate_match_namespace(subjects[subjindex], 
                                                 subject, 
                                                 cond[condindex]->positive);
        else
          tempsuccess = evaluate_match_signing(subjects[subjindex], 
                                               subject, 
                                               cond[condindex]->positive);


        if (tempsuccess != SUCCESS_UNDECIDED)
          success = tempsuccess;

        if (success == SUCCESS_DENY)
          goto end;

        subjindex++;
      }
    }
    condindex++;
  }

end:
  OPENSSL_free(subject);
  return success;
}

static int isselfsigned(X509*cert)
{
  return !X509_NAME_cmp(X509_get_subject_name(cert),
                        X509_get_issuer_name(cert));

}

static int evaluate_cert(X509 *cert, struct policy **namespaces)
{
  int result = SUCCESS_UNDECIDED;
  int policyindex = -1,
    currentindex = -1;

  /* self-signed certificates always pass */
  if (isselfsigned(cert)) {
    char *subject = X509_NAME_oneline(X509_get_subject_name(cert), NULL, 0);
    OPENSSL_free(subject);
    return SUCCESS_PERMIT;
  }
  while ((policyindex = find_policy(namespaces, cert, currentindex)) != -1) {
    struct policy *policy = namespaces[policyindex];

    result = restriction_evaluate_policy(cert, policy);

    if (result != SUCCESS_UNDECIDED)
      break;
    currentindex = policyindex;
  }
  
  return result;
}

static int restriction_evaluate_namespace(STACK_OF(X509) *chain, struct policy **namespaces)
{
  int size = sk_X509_num(chain);
  int i = 0;
  int result = 0;
  int start = 0, end = 0;
  int step = 0;

  if (size > 1 && isselfsigned(sk_X509_value(chain,0))) {
    /* reverse certificate ordering.  Reverse direction of visit */

    start = size - 1;
    end   = -1;
    step  = -1;
  }
  else {
    /* right order */
    start = 0;
    end   = size;
    step  = 1;
  }

  for (i = start; i != end; i += step) {
    int j;
    X509 *cert = sk_X509_value(chain, i);

    for (j = i; j >= 0; j--) {
      result = evaluate_cert(cert, namespaces);

      if (result != SUCCESS_UNDECIDED)
        break;
    }
  }

  if (result == SUCCESS_UNDECIDED) {
    result = SUCCESS_PERMIT;
  }

  return result;
}

static int restriction_evaluate_signing(STACK_OF(X509) *chain, struct policy **signings)
{
  int size = sk_X509_num(chain);
  int i = 0;
  int result = 0;

  for (i = 0; i < size; i++) {
    X509 *cert = sk_X509_value(chain, i);

    result = evaluate_cert(cert, signings);

    if (result != SUCCESS_UNDECIDED)
      break;
  }

  if (result == SUCCESS_UNDECIDED)
    result = SUCCESS_DENY;

  return result;
}

int PRIVATE restriction_evaluate(STACK_OF(X509) *chain, struct policy **namespaces,
			 struct policy **signings)
{
  int result = 0;

  result = restriction_evaluate_namespace(chain, namespaces);

  if (result == SUCCESS_UNDECIDED) {
    result = restriction_evaluate_signing(chain, signings);
  }
  return result;
}

static void free_condition(struct condition *cond)
{
  free(cond->original);
  free(cond->subjects);
  free(cond);
}

static void free_policy(struct policy *pol)
{
  free(pol->caname);

  listfree((char**)(pol->conds), (freefn)free_condition);
  free(pol);
}

void PRIVATE voms_free_policies(struct policy **policies)
{
  listfree((char**)policies, (freefn)free_policy);
}

static FILE *open_from_dir(char *path, char *filename)
{
  char *realpath=snprintf_wrap("%s%s", path, filename);
  FILE *file = NULL;

  file = fopen(realpath, "rb");

  free(realpath);

  return file;
}


void PRIVATE read_pathrestriction(STACK_OF(X509) *chain, char *path,
			  struct policy ***names, 
			  struct policy ***signs)
{
  int size = sk_X509_num(chain);
  char hashed[9];
  char *hash;
  char signing[25]   = "/XXXXXXXX.signing_policy";
  char namespace[21] = "/XXXXXXXX.namespaces";
  int i = 0, j = 0;
  FILE *file = NULL;

  for (i = 0; i < size; i++) {
    X509 *cert = sk_X509_value(chain, i);
    hash = gethash(cert, hashed);

    /* Determine file names */
    strncpy(signing + 1, hash, 8);
    strncpy(namespace + 1, hash, 8);

    file = open_from_dir(path, signing);
    if (file) {
      void *scanner = NULL;

      signinglex_init(&scanner);
      signingset_in(file, scanner);
      (void)signingparse(signs, scanner);
      signinglex_destroy(scanner);
      fclose(file);
    }

    j = 0;
    if (*signs) {
      while ((*signs)[j]) {
        if ((*signs)[j]->self)
          (*signs)[j]->caname = strdup(hash);
        j++;
      }
    }
			   
    file = open_from_dir(path, namespace);
    if (file) {
      void *scanner = NULL;

      namespaceslex_init(&scanner);
      namespacesset_in(file, scanner);
      (void)namespacesparse(names, scanner);
      namespaceslex_destroy(scanner);
      fclose(file);
    }

    if (*names) {
      int j = 0;

      while ((*names)[j]) {
        if ((*names)[j]->self)
          (*names)[j]->caname = strdup(hash);
        j++;
      }
    }
  }
}
