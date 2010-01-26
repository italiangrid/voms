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
/***************************************************************************
 *  filename  : GSISocketServer.h
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

#ifndef VOMS_GSISOCKETSERVER
#define VOMS_GSISOCKETSERVER

/** Include the secure socket globus definition. */

#include <stdio.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/ssl.h>

#include <string>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>

/** 
 * The secure Server.
 * This object acts as Server in the message exchange. It listens for client
 * connections and, when asked for, it receives, sets and sends back the reference to the
 * agent to be used for secure message exchange.
 * @author Salvatore Monforte salvatore.monforte@ct.infn.it
 * @author comments by Marco Pappalardo marco.pappalardo@ct.infn.it and Salvatore Monforte
 */
class GSISocketServer
{
 public:

  /**
   * Constructor.
   * @param p the secure server port.
   * @param b the backlog, that is the maximum number of outstanding connection requests.
   */
  GSISocketServer(int, void * = NULL, int=5, bool=true);
  /**
   * Destructor.
   * This method must be also implemented by object subclassing server socket.
   */
  virtual ~GSISocketServer();

  /**
   * Close the connection.
   */
  virtual void Close();
  virtual bool Open();
  virtual void CloseListener(void);
  virtual void CloseListened(void);

  /**
   * Listen for incoming connection requests.
   * Accept incoming requests and redirect communication on a dedicated port.
   * @param a a reference to the secure GSI Socket Agent sent by Client.
   * @return the GSI Socket Agent redirecting communication on a dedicated port.
   */
  virtual bool Listen();
  void SetLogger(void *log);
  void CleanSocket();
  bool Send(const std::string &s);
  bool Receive(std::string &s);
  bool Peek(int size, std::string &s);
  bool AcceptGSIAuthentication(void); 
  void AdjustBacklog(int b);
  bool ReOpen(int, int=5, bool=true);
  void SetTimeout(int);
  int  GetTimeout();

  void SetError(const std::string &g);
  void SetErrorOpenSSL(const std::string &message);

public:
  std::string    own_subject;
  std::string    own_ca;
  std::string    peer_subject;
  std::string    peer_ca;
  std::string    peer_serial;
  EVP_PKEY *own_key;
  EVP_PKEY *peer_key;
  X509 *own_cert;
  X509 *peer_cert;
  X509 *actual_cert;
  STACK_OF(X509) *own_stack;
  STACK_OF(X509) *peer_stack;
  SSL *ssl;
  SSL_CTX *ctx;
  BIO *conn;
  void *pvd;
  char           *cacertdir;
  EVP_PKEY       *upkey;
  X509           *ucert;
  STACK_OF(X509) *cert_chain;
  std::string error;

public:
  int port;
  bool opened;
  int sck;
  int backlog;
  int newsock;
  int timeout;
  bool newopened;
  bool mustclose;
  void *logh;
};

#endif

/*
  Local Variables:
  mode: c++
  End:
*/

