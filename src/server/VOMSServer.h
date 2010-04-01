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

#include "Server.h"

#include <openssl/evp.h>

#include "data.h"

class VOMSInitException {

 public:
  VOMSInitException(const std::string &er = "") : error(er) {}
  virtual ~VOMSInitException() throw () {}
  const std::string error; //: The error message
  virtual const char* what( void ) const throw () { return error.c_str(); }

};

class VOMSServer {
public:
  VOMSServer(int argc, char *argv[]);
  ~VOMSServer();
  void UpdateOpts(void);
  void Run();

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
  std::string     globuspwd;
  std::string     globusid;
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
};
#endif
