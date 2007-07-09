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
 *  filename  : GSISocketServer.cpp
 *  authors   : Salvatore Monforte <salvatore.monforte@ct.infn.it>
 *  copyright : (C) 2001 by INFN
 ***************************************************************************/

// $Id:

#include "config.h"

/** The globus secure shell API definitions. */
extern "C" {
#include "replace.h"

#include <sys/types.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "gssapi.h"
#include <memory.h>
#include <time.h>
#include <stdio.h>
#include <netdb.h>

#include <openssl/evp.h>
#include <openssl/buffer.h>
#include <openssl/crypto.h>
#include <openssl/objects.h>
#include <openssl/x509.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "credentials.h"
#include "globuswrap.h"
#include "log.h"
}

/** Functionalities for transmitting and receiveing tokens. */
#include "tokens.h"
//#include "newca.h"
/** This class header file. */
#include "Server.h"

extern int sockalarmed;
static void Error(void *logh);

/**
 * Constructor.
 * @param p the secure server port.
 * @param b the backlog, that is the maximum number of outstanding connection requests.
 */
GSISocketServer::GSISocketServer(int p, int v, void *l, int b, bool m) :
  version(v), own_subject(""), own_ca(""), peer_subject(""), 
  peer_ca(""), peer_serial(""), own_key(NULL), peer_key(NULL), own_cert(NULL), 
  peer_cert(NULL), port(p), opened(false), 
  credential(GSS_C_NO_CREDENTIAL), context(GSS_C_NO_CONTEXT), 
  backlog(b), newopened(false), mustclose(m), conflags(0), logh(l)
{
  int nid;

  if (OBJ_txt2nid("UID") == NID_undef)
    OBJ_create("0.9.2342.19200300.100.1.1","USERID","userId");
}

void GSISocketServer::SetTimeout(int sec)
{
  sockalarmed = sec;
}

int GSISocketServer::GetTimeout()
{
  return sockalarmed;
}

gss_ctx_id_t GSISocketServer::GetContext()
{
  return context;
}

bool
GSISocketServer::ReOpen(int p, int v, int b, bool m)
{
  Close();
  port = p;
  version = v;
  mustclose = m;
  backlog = b;
  return Open();
}

void 
GSISocketServer::SetLogger(void *l)
{
  logh = l;
}

bool 
GSISocketServer::Open()
{
  bool result = false;
  struct sockaddr_in myaddr_in;

  memset ((char *)&myaddr_in, 0, sizeof(struct sockaddr_in));
  
  myaddr_in.sin_family = AF_INET;
  myaddr_in.sin_addr.s_addr = INADDR_ANY;
  myaddr_in.sin_port=htons(port);

  if((sck = socket (AF_INET, SOCK_STREAM, 0)) == -1) {
    LOG(logh, LEV_ERROR, T_PRE, "Cannot create socket.\n");
    return false;
  }

  opened = true;
  unsigned int value = 1;
	
  setsockopt( sck, SOL_SOCKET, SO_REUSEADDR, (void *) &value, sizeof(socklen_t));
  result = ((bind(sck, (struct sockaddr*)&myaddr_in, sizeof(struct sockaddr_in)) != -1) && (listen(sck, backlog) != -1));

  if (!result)
    LOGM(VARP, logh, LEV_ERROR, T_PRE, "Cannot bind to socket %d!\n", port);
  return result;
}

void GSISocketServer::AdjustBacklog(int n)
{
  listen(sck, backlog);
}

/**
 * Destructor.
 */
GSISocketServer::~GSISocketServer()
{
  Close();
}


void GSISocketServer::CleanSocket()
{
  if (newopened) {
    struct linger l = {1,0};

    setsockopt(newsck, SOL_SOCKET, SO_LINGER, (void *)&l, sizeof(struct linger));
  }
}

/**
 * Close the connection.
 */
void 
GSISocketServer::Close()
{
  OM_uint32 status;

  if (context != GSS_C_NO_CONTEXT)
    gss_delete_sec_context(&status, &context, GSS_C_NO_BUFFER);
  context = GSS_C_NO_CONTEXT;
  if (credential != GSS_C_NO_CREDENTIAL)
    gss_release_cred(&status, &credential);
  credential = GSS_C_NO_CREDENTIAL;
  if (newopened)
    close(newsck);
  newopened=false;
  if (opened)
    close(sck);
  opened = false;
  if (peer_key)
    EVP_PKEY_free(peer_key);
  own_key = peer_key = NULL;
  own_cert = peer_cert = NULL;

  opened=false;
}

void GSISocketServer::CloseListener(void)
{
  if (opened)
    close(sck);
  opened = false;
}

void GSISocketServer::CloseListened(void)
{
  if (newopened)
    close(newsck);
  newopened = false;
}

void 
GSISocketServer::SetFlags(OM_uint32 flags)
{
  conflags = flags;
}

/**
 * Accept the GSI Authentication.
 * @param sock the socket for communication.
 * @param ctx the authorization context.
 * @return the context identifier. 
 */
bool
GSISocketServer::AcceptGSIAuthentication()
{
  OM_uint32      major_status = 0, minor_status = 0, status=0;
  OM_uint32      ret_flags = GSS_C_GLOBUS_SSL_COMPATIBLE;
  int            token_status = 0;
  char           *name = NULL;
  gss_cred_id_t  delegated_cred = GSS_C_NO_CREDENTIAL;

  if (!newopened)
    return false;

  if (context != GSS_C_NO_CONTEXT)
    gss_delete_sec_context(&status, &context, GSS_C_NO_BUFFER);
  context = GSS_C_NO_CONTEXT;
  if (credential != GSS_C_NO_CREDENTIAL)
    gss_release_cred(&status, &credential);
  credential = GSS_C_NO_CREDENTIAL;

  major_status = globus_gss_assist_acquire_cred(&minor_status,
                                                GSS_C_BOTH,
                                                &credential);
  if(GSS_ERROR(major_status)) {
    char *str = NULL;
    globus_gss_assist_display_status_str(&str,
					 "Failed to acquire credentials:",
					 major_status, minor_status, 0);
    LOG(logh, LEV_ERROR, T_PRE, str);
    free(str);
    return false;
  }

  major_status =
    globus_gss_assist_accept_sec_context(&minor_status, &context,
                                         credential, &name,
                                         &ret_flags, NULL,
                                         &token_status, &delegated_cred,
                                         &get_token, (void *) &newsck,
                                         &send_token, (void *) &newsck);

  if (GSS_ERROR(major_status)) {
    char *str = NULL;
    LOGM(VARP, logh, LEV_DEBUG, T_PRE, "Major: %x, minor: %x\n", major_status, minor_status); 
    globus_gss_assist_display_status_str(&str,
                                         "Failed to establish security context (accept):",
                                         major_status, minor_status, token_status);
    LOG(logh, LEV_ERROR, T_PRE, str);
    Error(logh);
    free(str);
    return false;
  }

  if ((ret_flags & conflags) != conflags) {
    LOGM(VARP, logh, LEV_ERROR, T_PRE, "Flags Mismatch:\nExpected: %d\nReceived:%d",
         conflags, (ret_flags & conflags));
    return false;
  }

  char *tmp = NULL;

  tmp = get_globusid(credential);
  if (tmp)
    own_subject = std::string(tmp);
  free(tmp);

  X509 *rcert = NULL;
  STACK_OF(X509) *stk = NULL;

  rcert = decouple_cred(credential, version, &stk);
  own_stack = stk;

  LOGM(VARP, logh, LEV_DEBUG, T_PRE, "Certificate DN: %s",
       X509_NAME_oneline(X509_get_subject_name(rcert), NULL, 0));
  LOGM(VARP, logh, LEV_DEBUG, T_PRE, "Certificate CA: %s",
       X509_NAME_oneline(X509_get_issuer_name(rcert), NULL, 0));
  LOGM(VARP, logh, LEV_DEBUG, T_PRE, "Stack Size: %d", sk_X509_num(stk));

  for (int i = 0; i < sk_X509_num(stk); i++) {
    X509 *cert = sk_X509_value(stk, i);
    LOGM(VARP, logh, LEV_DEBUG, T_PRE, "Certificate DN: %s",
         X509_NAME_oneline(X509_get_subject_name(cert), NULL, 0));
    LOGM(VARP, logh, LEV_DEBUG, T_PRE, "Certificate CA: %s",
         X509_NAME_oneline(X509_get_issuer_name(cert), NULL, 0));
  }

  tmp = NULL;
  (void)get_own_data(credential, version, &own_key, &tmp, &own_cert);
  if (tmp)
    own_ca = std::string(tmp);
  free(tmp);

  peer_subject = name; 

  tmp = NULL;
  (void)get_peer_data(context, version, &peer_key, &tmp, &peer_cert);
  if (tmp)
    peer_ca = std::string(tmp);
  free(tmp);

  char *serial = get_peer_serial(peer_cert);

  peer_serial = std::string(serial ? serial : "");
  free(serial);

  return true;
}

/**
 * Listen for incoming connection requests.
 * Accept incoming requests and redirect communication on a dedicated port.
 * @param a a reference to the secure GSI Socket Agent sent by Client.
 * @return the GSI Socket Agent redirecting communication on a dedicated port.
 */
bool 
GSISocketServer::Listen()
{
  struct sockaddr_in peeraddr_in;
  socklen_t addrlen = sizeof(struct sockaddr_in);

  if (!opened) {
    LOG(logh, LEV_ERROR, T_PRE, "Socket unopened!");
    return false;
  }

#ifndef HAVE_SOCKLEN_T
  newsck = accept(sck, (struct sockaddr*)&peeraddr_in, &((int)addrlen));
#else
  newsck = accept(sck, (struct sockaddr*)&peeraddr_in, &addrlen);
#endif

  if (newsck != -1) {
    /* Try to identify host */
#ifdef HAVE_SOCKLEN_T
    struct hostent * he = gethostbyaddr((void *)&peeraddr_in, (int)addrlen, AF_INET);
#else
    struct hostent * he = gethostbyaddr((void *)&peeraddr_in, addrlen, AF_INET);
#endif

    if (he) {
      if (he->h_name)
        LOGM(VARP, logh, LEV_INFO, T_PRE, "Received connection from: %s (%s)\n", he->h_name, inet_ntoa(peeraddr_in.sin_addr));
    }
    else
      LOGM(VARP, logh, LEV_INFO, T_PRE, "Received connection from: %s\n", inet_ntoa(peeraddr_in.sin_addr));

    newopened = true;
    return true;
  }
  else
    return false;
}

/**
 * Send a string value.
 * @param s the string value to send.
 * @return true on success, false otherwise.
 */ 
bool 
GSISocketServer::Send(const std::string s)
{
  if (!(context == GSS_C_NO_CONTEXT)) {
    OM_uint32        min_stat;
     
    int token_status;
    return (1 == my_send(&min_stat, context, const_cast<char *>(s.c_str()),
                         s.length(), &token_status, send_token, &newsck, logh));
  }

  return false;
}


/**
 * Receive a string value.
 * @param s the string to fill.
 * @return true on success, false otherwise.
 */
bool 
GSISocketServer::Receive(std::string& s)
{
  OM_uint32 maj_stat, min_stat;

  char  *message = NULL;
  size_t length;
  int    token_status;
  int ret = 0;

  ret = my_recv(&min_stat, context, &message, &length, &token_status, 
                get_token, &newsck, logh);

  if (ret) {
    s = std::string(message,length);
    free(message);
  }
  else {
    char *str = NULL;
    globus_gss_assist_display_status_str(&str, 
					 "GSS authentication failure ",
                                         ret, min_stat, token_status); 
    LOG(logh, LEV_ERROR, T_PRE, str);
    free(str);
  }

  return ret == 1;
}

static void Error(void *logh)
{
  unsigned long l;
  char buf[256];
#if SSLEAY_VERSION_NUMBER  >= 0x00904100L
  const char *file;
#else
  char *file;
#endif
  char *dat;
  int line;
    
  /* WIN32 does not have the ERR_get_error_line_data */ 
  /* exported, so simulate it till it is fixed */
  /* in SSLeay-0.9.0 */
  
  while ( ERR_peek_error() != 0 ) {
    
    int i;
    ERR_STATE *es;
      
    es = ERR_get_state();
    i = (es->bottom+1)%ERR_NUM_ERRORS;
    
    if (es->err_data[i] == NULL)
      dat = strdup("");
    else
      dat = strdup(es->err_data[i]);
    if (dat) {
      l = ERR_get_error_line(&file, &line);
      //      if (debug)
        LOGM(VARP, logh, LEV_ERROR, T_PRE, "%s:%s:%d:%s\n", ERR_error_string(l, buf), file, line, dat);
        //      else
        LOGM(VARP, logh, LEV_ERROR, T_PRE, "%s:%s\nFunction: %s\n", ERR_reason_error_string(l), dat, ERR_func_error_string(l));
    }
    
    free(dat);
  }

}
