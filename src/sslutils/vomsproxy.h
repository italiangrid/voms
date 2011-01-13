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

#ifndef VOMS_PROXY_H
#define VOMS_PROXY_H

#ifdef __cplusplus
extern "C" {
#endif

#include <openssl/x509.h>
#include <openssl/stack.h>
#include <openssl/evp.h>

#include "newformat.h"

struct VOMSProxyArguments {
  X509_REQ       *proxyrequest;
  char           *proxyfilename;
  char           *filename;
  AC            **aclist;
  int             proxyversion;
  char           *data;
  int             datalen;
  char           *newsubject;
  int             newsubjectlen;
  X509           *cert;
  EVP_PKEY       *key;
  int             bits;
  char           *policyfile;
  char           *policylang;
  char           *policytext;
  int             pathlength;
  int             hours;
  int             minutes;
  int             limited;
  char           *voID;
  int (*callback)();
  STACK_OF(X509_EXTENSION) *extensions;
  STACK_OF(X509) *chain;
  int             pastproxy;
  char           *keyusage;
  char           *netscape;
  char           *exkusage;
  char           *newissuer;
  char           *newserial;
  int             selfsigned;
};

struct VOMSProxy {
  X509 *cert;
  STACK_OF(X509) *chain;
  EVP_PKEY *key;
};

struct VOMSProxyArguments *VOMS_MakeProxyArguments();
void VOMS_FreeProxyArguments(struct VOMSProxyArguments *args);
void VOMS_FreeProxy(struct VOMSProxy *proxy);
struct VOMSProxy *VOMS_AllocProxy();
int VOMS_WriteProxy(const char *filename, struct VOMSProxy *proxy);
struct VOMSProxy *VOMS_MakeProxy(struct VOMSProxyArguments *args, int *warning, void **additional);
X509_EXTENSION *CreateProxyExtension(char * name, char *data, int datalen, int crit);
char *ProxyCreationError(int error, void *additional);

#define PROXY_ERROR_IS_WARNING(error) (error >= 1000)

#define PROXY_NO_ERROR                            0
#define PROXY_ERROR_OPEN_FILE                     1
#define PROXY_ERROR_STAT_FILE                     2
#define PROXY_ERROR_OUT_OF_MEMORY                 3
#define PROXY_ERROR_FILE_READ                     4
#define PROXY_ERROR_UNKNOWN_BIT                   5
#define PROXY_ERROR_UNKNOWN_EXTENDED_BIT          6
#define PROXY_WARNING_GSI_ASSUMED              1000
#define PROXY_WARNING_GENERIC_LANGUAGE_ASSUMED 1001

#ifdef __cplusplus
}
#endif

#endif
