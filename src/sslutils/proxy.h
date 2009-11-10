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

#ifndef VOMS_PROXY_H
#define VOMS_PROXY_H

#include <openssl/x509.h>
#include <openssl/stack.h>
#include <openssl/evp.h>

#include "newformat.h"

struct arguments {
  char           *proxyfilename;
  char           *filename;
  AC            **aclist;
  int             proxyversion;
  char           *data;
  int             datalen;
  char           *subject;
  int             subjectlen;
  X509           *cert;
  STACK_OF(X509) *chain;
  EVP_PKEY       *key;
  int             bits;
  char           *policyfile;
  char           *policylang;
  int             pathlength;
  int             hours;
  int             minutes;
  int             limited;
  char           *voID;
  int (*callback)();
};

struct proxy {
  X509 *cert;
  STACK_OF(X509) *chain;
  EVP_PKEY *key;
};

struct arguments *makeproxyarguments();
void freeproxyarguments(struct arguments *args);
void freeproxy(struct proxy *proxy);
struct proxy *allocproxy();
int writeproxy(const char *filename, struct proxy *proxy);
struct proxy *makeproxy(struct arguments *args, int *warning, void **additional);

#define PROXY_NO_ERROR                            0
#define PROXY_ERROR_OPEN_FILE                     1
#define PROXY_ERROR_STAT_FILE                     2
#define PROXY_ERROR_OUT_OF_MEMORY                 3
#define PROXY_ERROR_FILE_READ                     4
#define PROXY_WARNING_GSI_ASSUMED              1000
#define PROXY_WARNING_GENERIC_LANGUAGE_ASSUMED 1001

#endif
