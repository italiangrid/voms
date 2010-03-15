/*********************************************************************
 *
 * Authors: Vincenzo Ciaschini - Vincenzo.Ciaschini@cnaf.infn.it 
 *          Valerio Venturi - Valerio.Venturi@cnaf.infn.it 
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
#ifndef VOMS_UTILS_VOMSFAKE_H
#define VOMS_UTILS_VOMSFAKE_H

#include "config.h"

#include <string>
#include <vector>

extern "C" {

#include "openssl/bn.h"
  
#include "sslutils.h"
#include "newformat.h"
#include "parsertypes.h"  
}

enum message_type {FORCED, INFO, WARN, ERROR, DEBUG};

class Fake {

 private:

  std::string        program;

  std::string        confile;

  // PKI files
  char *             cacertfile;
  char *             certdir;
  char *             certfile;
  char *             keyfile;

  // output files
  char *             outfile;
  std::string        proxyfile;
  
  std::string        incfile;
  std::string        separate;
  std::string        uri;

  // proxy and AC settings */
  int                bits;
  int                hours;
  bool               limit_proxy;
  int                vomslife;
  int                proxyver;
  std::string        policyfile;
  std::string        policylang;
  int                pathlength;

  // verify the cert is good
  bool               verify;

  // doesn't regenerate proxy, use old
  bool               noregen;

  // globus version
  int                version;

  std::string        voms;
  std::string        targetlist;
  std::vector<std::string> fqans;
  
#ifdef CLASS_ADD
  void *             class_add_buf = NULL;
  size_t             class_add_buf_len = 0;
#endif
  
  X509 *ucert;
  EVP_PKEY *upkey;
  STACK_OF(X509) *cert_chain;
  proxy_verify_desc        pvd;
  proxy_verify_ctx_desc    pvxd;

  // store data retrieved from server
  AC **                    aclist;
  
  // vo
  std::string voID;

  std::string hostcert, hostkey;

  bool newformat;
  std::string newsubject;
  std::string newissuer;
 public:
  
  Fake(int argc, char** argv);
  ~Fake();
  bool Run();

 private:
  
  bool CreateProxy(std::string filedata, AC ** aclist, int version);

  bool Retrieve(VOLIST *list);
  
  // write AC and data retrieved form server to file
  bool WriteSeparate();
  
  // test if certificate used for signing is expired
  void Test();
  
  bool pcdInit();
  
  // verify the certificate is signed by a trusted CA
  bool Verify();
  
  // get openssl error */
  void Error();

  bool VerifyOptions();
  void exitError(const char *message);
  std::ostream& Print(message_type type);

  X509_EXTENSION *create_extension(const std::string &string);
  STACK_OF(X509_EXTENSION) *create_and_add_extension(const std::string &string, STACK_OF(X509_EXTENSION) *exts);

  bool rfc;
  std::string pastac;
  std::string pastproxy;
  std::string keyusage;
  std::string netscape;
  std::string exkusage;
  std::string newserial;

  std::vector<std::string> extensions;
  std::vector<std::string> acextensions;
  bool selfsigned;
};

#endif
