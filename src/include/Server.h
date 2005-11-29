/*********************************************************************
 *
 * Authors: Vincenzo Ciaschini - Vincenzo.Ciaschini@cnaf.infn.it 
 *
 * Copyright (c) 2002, 2003 INFN-CNAF on behalf of the EU DataGrid.
 * For license conditions see LICENSE file or
 * http://www.edg.org/license.html
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
#include "globus_gss_assist.h"

#include <stdio.h>
#include <openssl/evp.h>
#include <openssl/x509.h>

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
  GSISocketServer(int, int, void * = NULL, int=5, bool=true);
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
  /**
   * Redirects the GSI output.
   * This method allows to define a logging file for GSI.
   * @param fp a pinter to a file.
   */ 
  void RedirectGSIOutput(FILE *fp) { gsi_logfile = fp; }
  void SetFlags(OM_uint32 flags);
  void SetLogger(void *log);
  void CleanSocket();
  bool Send(std::string s);
  bool Receive(std::string &s);
  bool AcceptGSIAuthentication(void); 
  void AdjustBacklog(int b);
  bool ReOpen(int, int, int=5, bool=true);
  void SetTimeout(int);
  int  GetTimeout();
 private:
  /**
   * Accept the GSI Authentication.
   * @param sock the socket for communication.
   * @param ctx the authorization context.
   * @return the context identifier. 
   */
  /** The reference to the log file. */
  FILE *gsi_logfile;
  int version;

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

private:
  int port;
  bool opened;
  gss_cred_id_t credential;
  gss_ctx_id_t  context;
  int sck;
  int backlog;
  int newsck;
  bool newopened;
  bool mustclose;
  OM_uint32 conflags;
  void *logh;
};

#endif

/*
  Local Variables:
  mode: c++
  End:
*/

