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
/***************************************************************************
 *  filename  : GSISocketClient.h
 *  authors   : Salvatore Monforte <salvatore.monforte@ct.infn.it>
 *  copyright : (C) 2001 by INFN
 ***************************************************************************/

// $Id:

/**
 * @file GSISocketServer.h
 * @brief The header file for ssh based Socket Server Object.
 * This file contains definitions for secure Socket Server used in
 * order to communicate with the Resource Broker.\ It uses SSH standard.
 * @author Salvatore Monforte salvatore.monforte@ct.infn.it
 * @author comments by Marco Pappalardo marco.pappalardo@ct.infn.it and Salvatore Monforte
 */

#ifndef VOMS_GSISOCKETCLIENT
#define VOMS_GSISOCKETCLIENT

/** This super class header file. */
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/ssl.h>

#include <string>

#include <sys/types.h>
#include <sys/socket.h>

extern "C" {
#include "sslutils.h"
}

/** 
 * The secure Client.
 * This object acts as Client in the message exchange. It asks the client for
 * connections referencing an agent for secure message exchange.
 * @author Salvatore Monforte salvatore.monforte@ct.infn.it
 * @author comments by Marco Pappalardo marco.pappalardo@ct.infn.it and Salvatore Monforte
 */
class GSISocketClient
{

public:
  /**
   * Constructor.
   * @param p the secure server port.
   * @param b the backlog, that is the maximum number of outstanding connection requests.
   */
  GSISocketClient(const std::string&, int);
  /**
   * Destructor.
   */  
  ~GSISocketClient();

  /**
   * Open the connection.
   * @return true for successful opening, false otherwise.
   */
  bool Open();
  /**
   * Close the connection.
   * @return true for successful close, false otehrwise.
   */
  void Close();

  bool post_connection_check(SSL*);
  bool LoadCredentials(const char *, X509 *, STACK_OF(X509) *, EVP_PKEY *);

protected:
  /**
   * Initialize GSI Authentication.
   * This method asks the server for authentication.
   * @param sock the socket descriptot
   * @return true on success, false otherwise.
   */
  bool InitGSIAuthentication(int sock);

private:
  std::string host;
  int port;

  bool opened;
  int sck;

public:
  std::string     own_subject;
  EVP_PKEY       *upkey;
  X509           *ucert;
  STACK_OF(X509) *cert_chain;
  char           *cacertdir;
  SSL *ssl;
  SSL_CTX *ctx;
  BIO *conn;

  bool Send(const std::string &s);
  bool Receive(std::string &s);

private:
  std::string error;
  void SetError(const std::string&);
  void SetErrorGlobus(const std::string&, int, int, int);
  void SetErrorOpenSSL(const std::string& );

public:
  std::string GetError();
  void SetTimeout(int t);

private:
  int timeout;
};

#endif

/*
  Local Variables:
  mode: c++
  End:
*/





