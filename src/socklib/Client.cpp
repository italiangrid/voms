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
 *  filename  : GSISocketClient.cpp
 *  authors   : Salvatore Monforte <salvatore.monforte@ct.infn.it>
 *  copyright : (C) 2001 by INFN
 ***************************************************************************/

// $Id:

#include "config.h"

extern "C" {
#include "replace.h"

#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include "credentials.h"
#include <openssl/buffer.h>
#include <openssl/crypto.h>
#include <openssl/objects.h>
#include <openssl/x509.h>

#include "log.h"
#include "globuswrap.h"
}

/** This class header file. */
#include "Client.h"
/** The tokens transission and reception features definitions. */
#include "tokens.h"

//#include "newca.h"

/**
 * Constructor.
 * @param p the secure server port.
 * @param b the backlog, that is the maximum number of outstanding connection requests.
 */
GSISocketClient::GSISocketClient(const std::string h, int p, int v, void *l) :
  host(h), port(p), version(v), context(GSS_C_NO_CONTEXT),
  credential(GSS_C_NO_CREDENTIAL), _server_contact(""), conflags(0),
  opened(false), sck(-1), own_subject(""), own_ca(""),
  own_key(NULL), own_cert(NULL), peer_subject(""), peer_ca(""), 
  peer_key(NULL), peer_cert(NULL), logh(l), error("")
{
  OBJ_create("0.9.2342.19200300.100.1.1","USERID","userId");
}

/**
 * Destructor.
 */  
GSISocketClient::~GSISocketClient()
{
  Close();
}

void 
GSISocketClient::SetFlags(OM_uint32 f)
{
  conflags = f;
}

void GSISocketClient::SetLogger(void *l)
{
  logh = l;
}

void GSISocketClient::SetError(const std::string &g)
{
  error = g;
}

void GSISocketClient::SetErrorGlobus(const std::string &g, OM_uint32 maj, 
                                     OM_uint32 min, OM_uint32 tok)
{
  char *str = NULL;
  globus_gss_assist_display_status_str(&str, (char *)g.c_str(), maj, min, tok);
  SetError(str);
  free(str);
}
  
std::string GSISocketClient::GetError()
{
  return error;
}


/**
 * Initialize GSI Authentication.
 * This method asks the server for authentication.
 * @param sock the socket descriptot
 * @return true on success, false otherwise.
 */
bool 
GSISocketClient::InitGSIAuthentication(int sock)
{
   OM_uint32                   major_status = 0;
   OM_uint32                   minor_status = 0;
   OM_uint32                   status       = 0;

   OM_uint32                   req_flags  = conflags;
   OM_uint32                   ret_flags  = 0;
   int                         token_status = 0;
   char                        service[1024];


   if (credential != GSS_C_NO_CREDENTIAL)
     gss_release_cred(&status, &credential);
   credential = GSS_C_NO_CREDENTIAL;

   if (context != GSS_C_NO_CONTEXT)
     gss_delete_sec_context(&status, &context, GSS_C_NO_BUFFER);
   context= GSS_C_NO_CONTEXT;

   /* acquire our credentials */
   major_status = globus_gss_assist_acquire_cred(&minor_status,
						 GSS_C_BOTH,
						 &credential);

   if(major_status != GSS_S_COMPLETE) {
     char *str = NULL;
     globus_gss_assist_display_status_str(&str,
					  "Failed to acquire credentials: ",
					  major_status, minor_status, 0);
     LOGM(VARP, logh, LEV_ERROR, T_PRE, "Globus Error: %s", str);
     SetError(std::string("Globus Error: ") + str + "\nFailed to find valid user certificate!");
     free(str);
     if (credential != GSS_C_NO_CREDENTIAL)
       gss_release_cred(&status, &credential);
     return false;
   }
   
   char *tmp;
   
   tmp = get_globusid(credential);
   if (tmp)
     own_subject = std::string(tmp);
   free(tmp);

   tmp = NULL;
   (void)get_own_data(credential, version, &own_key, &tmp, &own_cert);
   if (tmp)
     own_ca = std::string(tmp);
   free(tmp);
   tmp = NULL;

   if (_server_contact.empty())
     snprintf(service, sizeof(service), "host@%s", host.c_str()); /* XXX */
   else
     snprintf(service, sizeof(service), "%s", _server_contact.c_str());

   /* initialize the security context */
   /* credential has to be fill in beforehand */
   major_status =
     globus_gss_assist_init_sec_context(&minor_status, credential,
                                        &context, service,
                                        req_flags, &ret_flags,
                                        &token_status,
                                        get_token, (void *) &sock,
                                        send_token, (void *) &sock);


   if(major_status != GSS_S_COMPLETE) {
     char *str = NULL;
     globus_gss_assist_display_status_str(&str,
					  "Failed to establish security context (init): ",
					  major_status, minor_status, token_status);
     LOGM(VARP, logh, LEV_ERROR, T_PRE, "Globus Error: %s", str);
     SetErrorGlobus("Could not establish authenticated connection with the server.", major_status, minor_status, token_status);
     free(str);
     if (credential != GSS_C_NO_CREDENTIAL)
       gss_release_cred(&status, &credential);
     if (context != GSS_C_NO_CONTEXT)
       gss_delete_sec_context(&status, &context, GSS_C_NO_BUFFER);

     return false;
   }

   peer_subject = _server_contact.empty() ? service : _server_contact; 
   get_peer_data(context, version, &peer_key, &tmp, &peer_cert);
   if (tmp)
     peer_ca = std::string(tmp);
   free(tmp);

   if ((ret_flags & req_flags) != req_flags) {
     LOGM(VARP, logh, LEV_ERROR, T_PRE, "Flags Mismatch:\nExpected: %d\nReceived:%d",
	  req_flags, (ret_flags & req_flags));
     if (credential != GSS_C_NO_CREDENTIAL)
       gss_release_cred(&status, &credential);
     if (context != GSS_C_NO_CONTEXT)
       gss_delete_sec_context(&major_status, &context, GSS_C_NO_BUFFER);
     if (peer_key) {
       EVP_PKEY_free(peer_key);
       peer_key = NULL;
     }
     SetError("Could not guarantee the requested QoS.");
     return false;
   }
   return true;
}

/**
 * Open the connection.
 * @return true for successful opening, false otherwise.
 */
bool 
GSISocketClient::Open()
{
  peeraddr_in.sin_family = AF_INET;
    
  struct hostent *hp; 
  char *syserr = NULL;
    
  if (!(hp = gethostbyname(host.c_str()))) {
    SetError("Host name unknown to DNS.");
    return false;
  }

  peeraddr_in.sin_addr.s_addr = ((struct in_addr *)(hp->h_addr))->s_addr;
  peeraddr_in.sin_port = htons(port);
  context = GSS_C_NO_CONTEXT;
  credential = GSS_C_NO_CREDENTIAL;

  if ((sck = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
    syserr = strerror(errno);
    SetError("Could not create socket. " + (syserr ? std::string(syserr) : ""));
    return false;
  }
  opened = true;

  unsigned char value;
  socklen_t len = sizeof(value);

  value = 1; // force reuse 
  setsockopt(sck, SOL_SOCKET, SO_REUSEADDR, (void *) &value, len );

  if(connect(sck, (struct sockaddr*)&peeraddr_in,
             sizeof(struct sockaddr_in)) == -1) {
    syserr = strerror(errno);
    SetError("Could not connect to socket. " + (syserr ? std::string(syserr) : ""));
    return false;
  }
    
  socklen_t addrlen = (socklen_t)sizeof(struct sockaddr_in);
  struct sockaddr_in myaddr_in;
  memset ((char *)&myaddr_in, 0, sizeof(struct sockaddr_in));
      
#ifndef HAVE_SOCKLEN_T
  if (getsockname(sck, (struct sockaddr*)&myaddr_in, &((int)addrlen)) == -1) {
#else
  if (getsockname(sck, (struct sockaddr*)&myaddr_in, &addrlen) == -1) {
#endif
    syserr = strerror(errno);
    SetError("Could not get socket name. " + (syserr ? std::string(syserr) : ""));
    return false;
  }
  return InitGSIAuthentication(sck);
}
  

/**
 * Close the connection.
 * @return true for successful close, false otherwise.
 */
void
GSISocketClient::Close()
{
  OM_uint32 status = 0;

  if (context != GSS_C_NO_CONTEXT)
     gss_delete_sec_context(&status, &context, GSS_C_NO_BUFFER);
  context= GSS_C_NO_CONTEXT;
  if (credential != GSS_C_NO_CREDENTIAL)
    gss_release_cred(&status,&credential);
  credential = GSS_C_NO_CREDENTIAL;
  if (opened)
    close(sck);
  if (peer_key) 
    EVP_PKEY_free(peer_key);
  peer_key = own_key = NULL;
  peer_cert = own_cert = NULL;

  opened=false;
}



/**
 * Send a string value.
 * @param s the string value to send.
 * @return true on success, false otherwise.
 */ 
bool 
GSISocketClient::Send(const std::string s)
{
  if (!(context == GSS_C_NO_CONTEXT)) {

    OM_uint32        maj_stat, min_stat;
     
    int token_status;
    int i = my_send(&min_stat, context,  const_cast<char *>(s.c_str()), 
                    s.length(), &token_status, send_token, &sck, logh);
    if (i)
      return 1;
    else {
      char *str = NULL;
      globus_gss_assist_display_status_str(&str, 
                                           "GSS authentication failure ",
                                           maj_stat, min_stat, token_status); 
      LOG(logh, LEV_ERROR, T_PRE, str);
      SetError(str);
      free(str);
    }
  }

  SetError("No context established.");
  return false;
}


/**
 * Receive a string value.
 * @param s the string to fill.
 * @return true on success, false otherwise.
 */
bool 
GSISocketClient::Receive(std::string& s)
{
  OM_uint32 maj_stat, min_stat;

  char  *message = NULL;
  size_t length;
  int    token_status;
  int ret = 0;

  ret = my_recv(&min_stat, context, &message, &length, &token_status, 
		get_token, &sck, logh);

  if (ret)
    s = std::string(message,length);
  else {
    char *str = NULL;
    globus_gss_assist_display_status_str(&str, 
					 "GSS authentication failure ",
           ret, min_stat, token_status); 
    LOG(logh, LEV_ERROR, T_PRE, str);
    SetError(str);
    free(str);
  }

  free(message);
  return ret == 1;
}
