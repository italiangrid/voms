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

extern "C" {
#include "replace.h"
#include <stdio.h>
#include <ctype.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#include "sslutils.h"
#include "log.h"
#include "credentials.h"
}

#include <string>
#include <iostream>
#include "soapH.h"
#include "VOMSServer.h"
#include "fqan.h"
#include "data.h"

static int (*pw_cb)() = NULL;
static char *canonicalize_string(char *original);
static bool makeACSSL(vomsresult &vr, SSL *ssl, const std::string& command, const std::string &orderstring, const std::string& targets, int requested, VOMSServer *v);
static int makeACREST(struct soap *soap, const std::string& command, const std::string& orderstring, const std::string& targets, int requested, int unknown);
int http_get(soap *soap);
static int pwstdin_callback(char * buf, int num, UNUSED(int w));
static bool get_parameter(char **path, char **name, char **value);

extern VOMSServer *selfpointer;
extern void *logh;
extern char *maingroup;

static int pwstdin_callback(char * buf, int num, UNUSED(int w)) 
{
  int i;
  
  if (!(fgets(buf, num, stdin))) {
    std::cerr << "Failed to read pass-phrase from stdin" << std::endl;
    return -1;
  }
  i = strlen(buf);
  if (buf[i-1] == '\n') {
      buf[i-1] = '\0';
      i--;
  }
  return i;	
  
}


static bool
makeACSSL(vomsresult &vr, SSL *ssl, const std::string& command, const std::string &orderstring, const std::string& targets, int requested, VOMSServer *v)
{
  X509 *holder = SSL_get_peer_certificate(ssl);
  STACK_OF(X509) *chain = SSL_get_peer_cert_chain(ssl);

  X509 *realholder = get_real_cert(holder, chain);
  X509 *issuer = NULL;
  EVP_PKEY *key = NULL;
  pw_cb =(int (*)())(pwstdin_callback);
  char *hostcert = (char*)"/etc/grid-security/hostcert.pem";
  char *hostkey  = (char*)"/etc/grid-security/hostkey.pem";

  if (!v->x509_user_cert.empty())
    hostcert = (char*)v->x509_user_cert.c_str();

  if (!v->x509_user_key.empty())
    hostkey = (char *)v->x509_user_key.c_str();

  if (!load_credentials(hostcert, hostkey, 
                        &issuer, NULL,  &key, pw_cb)) {
    X509_free(issuer);
    EVP_PKEY_free(key);
    return false;
  }

  std::string message = XML_Req_Encode(command, orderstring, targets, requested);

  bool ret = selfpointer->makeAC(vr, key, issuer, realholder, message);
  X509_free(issuer);
  EVP_PKEY_free(key);

  return ret;
}

static int
makeACREST(struct soap *soap, const std::string& command, const std::string& orderstring, const std::string& targets, int requested, int unknown)
{
  vomsresult vr;

  if (unknown)
    vr.setError(WARN_UNKNOWN_COMMAND, "Unknown parameters in the request were ignored!");

  (void)makeACSSL(vr, soap->ssl, command, orderstring, targets, requested, selfpointer);

  int value;
  std::string output = vr.makeRESTAnswer(value);

  soap->http_content = "text/xml";
  soap_response(soap, value);
  soap_send(soap, output.c_str());
  soap_end_send(soap);

  return SOAP_OK;
}

int http_get(soap *soap)
{
  char *path = strdup(soap->path);
  int unknown = 0;

  LOGM(VARP, logh, LEV_DEBUG, T_PRE, "REST Request: %s", soap->path);

  if (!path)
    return SOAP_GET_METHOD;

  char *s = strchr(path, '?');

  if (s)
    *s='\0';

  char *prepath=canonicalize_string(path);

  if (strcmp(prepath, "/generate-ac") != 0) {
    free(path);
    soap_response(soap, 404);
    soap_end_send(soap);
    return 404;
  }

  soap_response(soap, SOAP_HTML);

  /* determine parameters */
  std::vector<std::string> fqans;
  int lifetime = -1;
  std::string orderstring;
  std::string targetstring;

  if (s) {
    ++s;

    if (!strlen(s)) {
      free(path);
      soap_response(soap, 404);
      soap_end_send(soap);
      return 500;
    }

    char *basis = s;

    do {
      char *cname;
      char *cvalue;

      if (!get_parameter(&basis, &cname, &cvalue)) {
        free(path);
        soap_response(soap, 404);
        soap_end_send(soap);
        return 500;
      }

      if (strcmp(cname, "lifetime") == 0)
        lifetime = atoi(cvalue);

      else if (strcmp(cname, "fqans") == 0) {
        char *position = strchr(cvalue, ',');

        while (position) {
          *position = '\0';
          fqans.push_back(std::string(cvalue));
          cvalue = ++position;
          position = strchr(cvalue, ',');
        }
        fqans.push_back(std::string(cvalue));
      }

      else if (strcmp(cname, "order") == 0) {
        if (orderstring.empty())
          orderstring = std::string(cvalue);
        else
          orderstring += ", " + std::string(cvalue);
      }
      else if (strcmp(cname, "targets") == 0) {
        targetstring = std::string(cvalue);
      }
      else {
        /* purposefully ignore other parameters */
        /* but put it in an otherwise positive response */
        unknown = 1;
      }
    } while (basis);
  }

  if (fqans.size()==0)
    fqans.push_back(maingroup);

  std::string command = parse_fqan(fqans);

  int res = makeACREST(soap, command, orderstring, targetstring, lifetime, unknown);

  free(path);

  return res;
}

static bool get_parameter(char **path, char **name, char **value)
{
  if (!path || !name || !value)
    return false;

  char* next = strchr(*path, '&');

  if (next)
    *next='\0';

  char *equal = strchr(*path, '=');

  if (!equal)
    return false;

  *equal='\0';

  *name = *path;
  *value = equal+1;

  if (next)
    *path = ++next;
  else 
    *path = next;

  return true;
}

static char *canonicalize_string(char *original)
{
  char *currentin  = original;
  char *currentout = original;

  while (*currentin != '\0') {
    if (*currentin != '%')
      *currentout++ = *currentin++;
    else {
      char first = *(currentin+1);

      if (first != '\0') {
        char second = *(currentin+2);

        if (second != '\0') {
          if (isxdigit(first) && isxdigit(second)) {
            *currentout++=hex2num(first)<<4 + hex2num(second);
            currentin += 3;
          }
          else
            *currentout++ = *currentin++;
        }
        else
          *currentout++ = *currentin++;
      }
      else
        *currentout++ = *currentin++;
    }
  }
  *currentout='\0';

  return original;
}

