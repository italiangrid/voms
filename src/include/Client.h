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
#include <netinet/in.h>
#include <netdb.h>

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
  GSISocketClient(const std::string&, int, int);
  /**
   * Destructor.
   */  
  virtual ~GSISocketClient();

  void RedirectGSIOutput(FILE *fp) { gsi_logfile = fp; }
  /**
   * Set the server contact. 
   * @param contact the server contact string to set.
   */
  void ServerContact(const std::string& contact) { _server_contact = contact; }
  /**
   * Sets required connection flags.
   * @param flags is a bitwise or of all the flags required.
   */
  //  void SetFlags(int flags);


  /**
   * Open the connection.
   * @return true for successful opening, false otherwise.
   */
  virtual bool Open();
  /**
   * Close the connection.
   * @return true for successful close, false otehrwise.
   */
  virtual void Close();

  virtual bool post_connection_check(SSL*);
  virtual bool LoadCredentials(const char *, X509 *, STACK_OF(X509) *, EVP_PKEY *);

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
  int version;
   /** The Secure Shell context identifier. */
  gss_ctx_id_t context; 
  gss_cred_id_t credential;
  std::string _server_contact;
   //bool _do_mutual_authentication;
  FILE *gsi_logfile;
  bool opened;
  int sck;

public:
  std::string     own_subject;
  std::string     own_ca;
  EVP_PKEY       *upkey;
  X509           *ucert;
  STACK_OF(X509) *cert_chain;
  char           *cacertdir;
  std::string     peer_subject;
  std::string     peer_ca;
  EVP_PKEY       *peer_key;
  X509           *peer_cert;
  SSL *ssl;
  SSL_CTX *ctx;
  BIO *conn;
  void *pvd;

  bool Send(const std::string &s);
  bool Receive(std::string &s);

private:
  struct sockaddr_in peeraddr_in;	/**< Address for peer socket.*/
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





