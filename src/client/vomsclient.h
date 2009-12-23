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
#ifndef VOMS_CLIENT_VOMSCLIENT_H
#define VOMS_CLIENT_VOMSCLIENT_H

#include <string>
#include <vector>
#include <ostream>
#include <exception>
#include "voms_api.h"

extern "C" {

#include "openssl/bn.h"
  
#include "sslutils.h"
#include "newformat.h"
  
}

enum message_type {FORCED, INFO, WARN, ERROR, DEBUG};

class VOMSException : public std::exception 
{
 public:
  VOMSException(const std::string &er = "") : error(er) {}
  ~VOMSException() throw () {}
  const std::string error; //: The error message
  virtual const char* what( void ) const throw () { return error.c_str(); }
};

class Client {

 private:

  std::string        program;

  bool               ignorewarn;
  bool               failonwarn;

  // PKI files
  char *             cacertfile;
  char *             certdir;
  char *             certfile;
  char *             keyfile;

  // output files
  char *             outfile;
  std::string        proxyfile;
  
  // special location for configuration files */
  std::string        confile;
  std::string        userconf;

  
  std::string        incfile;
  std::string        separate;

  // proxy and AC settings */
  int                bits;
  int                hours;
  int                minutes;
  int                ac_hours;
  int                ac_minutes;
  bool               limit_proxy;
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

  std::vector<std::string> vomses;
  std::string              ordering;
  std::string              targetlist;
  std::vector<std::string> confiles;
#ifdef CLASS_ADD
  void *                   class_add_buf;
  size_t                   class_add_buf_len;
#endif

  BIGNUM *                 dataorder;
  //  proxy_cred_desc *        pcd;
  proxy_verify_desc        pvd;
  proxy_verify_ctx_desc    pvxd;

  // store data retrieved from server
  AC **                    aclist;
  std::string              data;
  
  // vo
  std::string voID;
  bool                     listing;
  STACK_OF(X509)           *cert_chain;
  X509                     *ucert;
  EVP_PKEY                 *private_key;
  int                       timeout;
  std::string               acfile;
  vomsdata                 *v;

 public:
  
  Client(int argc, char** argv);
  ~Client();
  bool Run();

 private:
  
  bool CreateProxy(std::string data, AC ** aclist, int version);

  bool AddToList(AC *ac);
  
  // write AC and data retrieved form server to file
  bool WriteSeparate();
  
  // test if certificate used for signing is expired
  bool Test();
  
  bool pcdInit();
  
  // verify the certificate is signed by a trusted CA
  bool Verify(bool doproxy);
  
  // get openssl error */
  void Error();

  bool LoadVomses();
  std::ostream& Print(message_type type);
  bool checkstats(char *file, int mode);
  void ProxyCreationError(int, void *);
  AC *ReadSeparate(const std::string&);
};
#endif
