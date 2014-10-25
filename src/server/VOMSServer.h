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
#ifndef VOMS_SERVER_VOMSSERVER_H
#define VOMS_SERVER_VOMSSERVER_H

#include <iostream>
#include <fstream>
#include <vector>
#include <string>

#include "Server.h"
#include "errors.h"
#include "vomsxml.h"

#include <openssl/evp.h>

#include "data.h"
#include <stdexcept>


struct voms_init_error: public std::runtime_error {
  voms_init_error(std::string const& m): 
    runtime_error(m){}
  virtual const char* what() throw() {
    return std::runtime_error::what();
  }
};

struct voms_execution_error: public std::runtime_error {
  voms_execution_error(std::string const& m): 
    runtime_error(m){}
  virtual const char* what() throw() {
    return std::runtime_error::what();
  }
};

class vomsresult {
private:
  std::string ac;
  std::string data;
  std::vector<errorp> errs;
  bool base64;

public:
  vomsresult() : ac("A"), data(""), base64(true) {};

  void setError(int num, std::string message) 
  {
    errorp t;
    t.num = num;
    t.message = message;
    errs.push_back(t);
  }

  void setError(errorp p) 
  {
    errs.push_back(p);
  }

  void setBase64(bool b64)
  {
    base64 = b64;
  }

  void setAC(std::string ac)
  {
    this->ac = ac;
  }

  void setData(std::string data)
  {
    this->data = data;
  }

  std::string makeXMLAnswer(void)
  {
    return XML_Ans_Encode(ac, data, errs, base64);
  }

  std::string makeRESTAnswer(int& code);
};

class VOMSServer {
public:
  VOMSServer(int argc, char *argv[]);
  ~VOMSServer();
  void UpdateOpts(void);
  void Run();
  bool makeAC(vomsresult& vr, EVP_PKEY *key, X509 *issuer, 
	      X509 *holder, const std::string &message);

private:
  VOMSServer &operator=(VOMSServer const &) {exit(1);}
  void Execute(EVP_PKEY *, X509 *, X509 *);

public:
  GSISocketServer sock;
  int             ac;
  char          **av;
  int             validity;
  std::string     logfile;
  bool            gatekeeper_test;
  int             daemon_port;
  bool            foreground;
  std::string     x509_cert_dir;
  std::string     x509_cert_file;
  std::string     x509_user_proxy;
  std::string     x509_user_cert;
  std::string     x509_user_key;
  std::string     desired_name_char;
  std::string     username;
  std::string     dbname;
  std::string     contactstring;
  int             mysql_port;
  std::string     mysql_socket;
  std::string     passfile;
  std::string     voname;
  std::string     uri;
  int             version;
  std::string     subject;
  std::string     ca;
  bool            debug;
  int             code;
  int             backlog;
  void           *logger;
  int             socktimeout;
  int             logmax;
  int             loglev;
  int             logt;
  std::string     logdf;
  std::string     logf;
  bool            newformat;
  bool            insecure;
  bool            shortfqans;
  bool            do_syslog;
  bool            base64encoding;
  bool            nologfile;
  int             max_active_requests;
};
#endif
