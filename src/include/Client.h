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


extern "C" {
/** Include the secure socket globus definition. */
#include <globus_gss_assist.h>

/** This super class header file. */
#include <openssl/evp.h>
#include <openssl/x509.h>
}

#include <string>

extern "C" {
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
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
  GSISocketClient(const std::string, int, int, void* = NULL);
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
  void SetFlags(OM_uint32 flags);


  void SetLogger(void *l);

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
  OM_uint32 conflags;
  FILE *gsi_logfile;
  bool opened;
  int sck;

public:
  std::string    own_subject;
  std::string    own_ca;
  EVP_PKEY      *own_key;
  X509          *own_cert;
  std::string    peer_subject;
  std::string    peer_ca;
  EVP_PKEY      *peer_key;
  X509          *peer_cert;
  void          *logh;

  bool Send(std::string s);
  bool Receive(std::string &s);

private:
  struct sockaddr_in peeraddr_in;	/**< Address for peer socket.*/
  std::string error;
  void SetError(const std::string&);
  void SetErrorGlobus(const std::string&, OM_uint32, OM_uint32, OM_uint32);

public:
  std::string GetError();
};

#endif

/*
  Local Variables:
  mode: c++
  End:
*/





