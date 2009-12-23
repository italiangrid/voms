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
#include <sys/select.h>
#include <time.h>
#include <netinet/in.h>
#include <netdb.h>
#include "credentials.h"
#include <openssl/buffer.h>
#include <openssl/crypto.h>
#include <openssl/objects.h>
#include <openssl/x509.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <unistd.h>
#include <fcntl.h>

#include "log.h"
#include "sslutils.h"
}

#include "ipv6sock.h"

#include <cstring>
#include "data.h"

/** This class header file. */
#include "Client.h"
/** The tokens transission and reception features definitions. */
#include "tokens.h"

/**
 * Constructor.
 * @param p the secure server port.
 * @param b the backlog, that is the maximum number of outstanding connection requests.
 */
GSISocketClient::GSISocketClient(const std::string &h, int p, int v) :
  host(h), port(p), version(v), context(0L),
  credential(0L), _server_contact(""), /* conflags(0),*/
  opened(false), own_subject(""), own_ca(""),
  upkey(NULL), ucert(NULL), cacertdir(NULL),
  peer_subject(""), peer_ca(""), 
  peer_key(NULL), peer_cert(NULL), ssl(NULL), ctx(NULL),
  conn(NULL), pvd(NULL), error(""), timeout(-1)
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

void GSISocketClient::SetTimeout(int t)
{
  timeout= t;
}

void GSISocketClient::SetError(const std::string &g)
{
  error = g;
}

void GSISocketClient::SetErrorOpenSSL(const std::string &message)
{
  error = message;

  unsigned long l;
  char buf[256];
#if SSLEAY_VERSION_NUMBER  >= 0x00904100L
  const char *file;
#else
  char *file;
#endif
  int line;
    
  /* WIN32 does not have the ERR_get_error_line_data */ 
  /* exported, so simulate it till it is fixed */
  /* in SSLeay-0.9.0 */
  
  while ( ERR_peek_error() != 0 ) {
    
    l = ERR_get_error_line(&file, &line);

    std::string temp;
    int code = ERR_GET_REASON(l);
    char *message = NULL;

    switch (code) {
    case SSL_R_SSLV3_ALERT_CERTIFICATE_EXPIRED:
      error += "Either proxy or user certificate are expired.";
      break;

    default:
      message = (char*)ERR_reason_error_string(l);
      error += std::string(ERR_error_string(l, buf))+ ":" + 
	std::string(file) + ":" + stringify(line, temp) + "\n";
      if (message)
	error += std::string(ERR_reason_error_string(l)) + ":" + 
	  std::string(ERR_func_error_string(l)) + "\n";
      break;
    }
  }
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
GSISocketClient::post_connection_check(SSL *ssl)
{
  X509 *peer_cert = SSL_get_peer_certificate(ssl);
  if (!peer_cert)
    return false;

  char *name = X509_NAME_oneline(X509_get_subject_name(peer_cert), NULL, 0);
  peer_subject = std::string(name);
  OPENSSL_free(name);

  return true;
}


bool GSISocketClient::LoadCredentials(const char *cadir, X509 *cert, STACK_OF(X509) *chain, EVP_PKEY *key)
{
  ucert = cert;
  cert_chain = chain;
  upkey = key;
  if (cadir)
    cacertdir = strdup((char*)cadir);
  else
    cacertdir = strdup("/etc/grid-security/certificates");

  char *name = NULL;

  name = X509_NAME_oneline(X509_get_subject_name(ucert), NULL, 0);
  own_subject = std::string(name);
  OPENSSL_free(name);

  name = X509_NAME_oneline(X509_get_issuer_name(ucert), NULL, 0);
  own_ca = std::string(name);
  OPENSSL_free(name);

  return true;
}

extern "C" {
 extern int proxy_app_verify_callback(X509_STORE_CTX *, void *);
}


proxy_verify_desc *setup_initializers(char *cadir) 
{
  proxy_verify_ctx_desc *pvxd = NULL;
  proxy_verify_desc *pvd = NULL;

  pvd  = (proxy_verify_desc*)     malloc(sizeof(proxy_verify_desc));
  pvxd = (proxy_verify_ctx_desc *)malloc(sizeof(proxy_verify_ctx_desc));
  pvd->cert_store = NULL;


  if (!pvd || !pvxd) {
    free(pvd);
    free(pvxd);
    return NULL;
  }

  proxy_verify_ctx_init(pvxd);
  proxy_verify_init(pvd, pvxd);

  pvd->pvxd->certdir = cadir;

  return pvd;

}

static void destroy_initializers(void *data) 
{
  proxy_verify_desc *pvd = (proxy_verify_desc *)data;

  if (pvd) {
    if (pvd->pvxd)
      proxy_verify_ctx_release(pvd->pvxd);

    free(pvd->pvxd);
    pvd->pvxd = NULL;
    proxy_verify_release(pvd);

    /* X509_STORE_CTX_free segfaults if passed a NULL store_ctx */
    if (pvd->cert_store)
      X509_STORE_CTX_free(pvd->cert_store);
    pvd->cert_store = NULL;

    free(pvd);
  }
}

extern "C" {
int proxy_verify_callback_server(X509_STORE_CTX *ctx, UNUSED(void *empty))
{

  return proxy_app_verify_callback(ctx, NULL);
}

int proxy_verify_callback_client(int ok, X509_STORE_CTX *ctx)
{
  return proxy_verify_callback(ok, ctx);
}

void setup_SSL_proxy_handler(SSL *ssl, char *cadir)
{
  SSL_set_ex_data(ssl, PVD_SSL_EX_DATA_IDX, 
                  setup_initializers(cadir));
}

void destroy_SSL_proxy_handler(SSL *ssl)
{
  if (ssl) {
    destroy_initializers(SSL_get_ex_data(ssl,
                                PVD_SSL_EX_DATA_IDX));
  }
}

}

/*
 * Encapsulates select behaviour
 *
 * Returns:
 *     > 0 : Ready to read or write.
 *     = 0 : timeout reached.
 *     < 0 : error.
 */
int do_select(int fd, fd_set *rset, fd_set *wset, int starttime, int timeout, int wanted)
{
  time_t curtime;

  FD_ZERO(rset);
  FD_ZERO(wset);

  if (wanted == 0 || wanted == SSL_ERROR_WANT_READ)
    FD_SET(fd, rset);
  if (wanted == 0 || wanted == SSL_ERROR_WANT_WRITE)
    FD_SET(fd, wset);

  timeval endtime;

  if (timeout != -1) {
    curtime = time(NULL);

    if (curtime - starttime >= timeout)
      return 0;

    endtime.tv_sec = timeout - (curtime - starttime);
    endtime.tv_usec = 0;
  }

  int ret = 0;

  if (timeout == -1)
    ret = select(fd+1, rset, wset, NULL, NULL);
  else
    ret = select(fd+1, rset, wset, NULL, &endtime);

  if (ret == 0)
    return 0;

  if ((wanted == SSL_ERROR_WANT_READ && !FD_ISSET(fd, rset)) ||
      (wanted == SSL_ERROR_WANT_WRITE && !FD_ISSET(fd,wset)))
    return -1;

  if (ret < 0 && (!FD_ISSET(fd, rset) || !FD_ISSET(fd, wset)))
    return 1;

  return ret;
}

/**
 * Open the connection.
 * @return true for successful opening, false otherwise.
 */
bool 
GSISocketClient::Open()
{
  SSL_METHOD *meth = NULL;
  int ret = -1, ret2 = -1;
  time_t starttime, curtime;
  long errorcode = 0;
  int fd = -1;
  std::string hostport;
  std::string temp;
  int expected = 0;
  char portstring[36];
  int flags;

  meth = SSLv3_method();

  ctx = SSL_CTX_new(meth);

  if (!ctx) {
    SetErrorOpenSSL("Cannot create context.");
    goto err;
  }

  SSL_CTX_set_options(ctx, SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS | SSL_OP_NO_TLSv1 | SSL_OP_NO_SSLv2);
  SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, proxy_verify_callback);
  SSL_CTX_set_verify_depth(ctx, 100);
  //  SSL_CTX_set_cert_verify_callback(ctx, proxy_app_verify_callback, setup_initializers());
  SSL_CTX_load_verify_locations(ctx, NULL, cacertdir);
  SSL_CTX_use_certificate(ctx, ucert);
  SSL_CTX_use_PrivateKey(ctx, upkey);
  SSL_CTX_set_cipher_list(ctx, "ALL:!LOW:!EXP:!MD5:!MD2");    
  SSL_CTX_set_purpose(ctx, X509_PURPOSE_ANY);
  SSL_CTX_set_mode(ctx, SSL_MODE_AUTO_RETRY);
  

  if (cert_chain) {
    /*
     * Certificate was a proxy with a cert. chain.
     * Add the certificates one by one to the chain.
     */
    X509_STORE_add_cert(ctx->cert_store, ucert);
    for (int i = 0; i <sk_X509_num(cert_chain); ++i) {
      X509 *cert = (sk_X509_value(cert_chain,i));

      if (!X509_STORE_add_cert(ctx->cert_store, cert)) {
        if (ERR_GET_REASON(ERR_peek_error()) == X509_R_CERT_ALREADY_IN_HASH_TABLE) {
          ERR_clear_error();
          continue;
        }
        else {
          SetErrorOpenSSL("Cannot add certificate to the SSL context's certificate store");
          goto err;
        }
      }
    }
  }

  snprintf(portstring, 35, "%ld", port);
  fd = sock_connect(host.c_str(), portstring, NULL);

  flags = fcntl(fd, F_GETFL, 0);
  (void)fcntl(fd, F_SETFL, flags | O_NONBLOCK);

  conn = BIO_new_socket(fd, BIO_NOCLOSE);
  (void)BIO_set_nbio(conn,1);

  ssl = SSL_new(ctx);
  setup_SSL_proxy_handler(ssl, cacertdir);
  SSL_set_bio(ssl, conn, conn);

  conn = NULL;

  curtime = starttime = time(NULL);

  fd_set rset;
  fd_set wset;

  do {
    ret = do_select(fd, &rset, &wset, starttime, timeout, expected);
    if (ret > 0) {
      ret2 = SSL_connect(ssl);
      curtime = time(NULL);
      expected = errorcode = SSL_get_error(ssl, ret2);
    }
  } while (ret > 0 && (ret2 <= 0 && ((timeout == -1) ||
           ((timeout != -1) &&
            (curtime - starttime) < timeout)) &&
           (errorcode == SSL_ERROR_WANT_READ ||
            errorcode == SSL_ERROR_WANT_WRITE)));

  if (ret2 <= 0 || ret <= 0) {
    if (timeout != -1 && (curtime - starttime <= timeout))
      SetError("Connection stuck during handshake: timeout reached.");
    else
      SetErrorOpenSSL("Error during SSL handshake:");
    goto err;
  }

  if (post_connection_check(ssl)) {
    opened = true;
    (void)Send("0");
    return true;
  }

 err:
  destroy_SSL_proxy_handler(ssl);
  SSL_free(ssl);
  SSL_CTX_free(ctx);
  BIO_free(conn);

  return false;
}
  

/**
 * Close the connection.
 * @return true for successful close, false otherwise.
 */
void
GSISocketClient::Close()
{
  if (opened) {
    context = 0L;
    credential = 0L;

    EVP_PKEY_free(peer_key);
    peer_key = upkey = NULL;
    peer_cert = ucert = NULL;
    cert_chain = NULL;

    SSL_clear(ssl);
    destroy_SSL_proxy_handler(ssl);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    BIO_free(conn);

    opened=false;
  }
}


/**
 * Send a string value.
 * @param s the string value to send.
 * @return true on success, false otherwise.
 */ 
bool 
GSISocketClient::Send(const std::string &s)
{
  if (!ssl) {
    SetError("No connection established");
    return false;
  }

  ERR_clear_error();

  int ret = 0, nwritten=0;

  const char *str = s.c_str();

  int fd = BIO_get_fd(SSL_get_rbio(ssl), NULL);
  time_t starttime, curtime;

  fd_set rset;
  fd_set wset;
  bool do_continue = false;
  int expected = 0;

  curtime = starttime = time(NULL);

  do {
    ret = do_select(fd, &rset, &wset, starttime, timeout, expected);
    do_continue = false;
    if (ret > 0) {
      ret = SSL_write(ssl, str + nwritten, strlen(str) - nwritten);
      curtime = time(NULL);
      switch (SSL_get_error(ssl, ret)) {
      case SSL_ERROR_NONE:
        nwritten += ret;
        if ((size_t)nwritten == strlen(str))
          do_continue = false;
        else
          do_continue = true;
        break;

      case SSL_ERROR_WANT_READ:
        expected = SSL_ERROR_WANT_READ;
        ret = 1;
        do_continue = true;
        break;
        
      case SSL_ERROR_WANT_WRITE:
        expected = SSL_ERROR_WANT_WRITE;
        ret = 1;
        do_continue = true;
        break;

      default:
        do_continue = false;
      }
    }
  } while (ret <= 0 && do_continue);
            
  if (ret <=0) {
    if (timeout != -1 && (curtime - starttime <= timeout))
      SetError("Connection stuck during write: timeout reached.");
    else
      SetErrorOpenSSL("Error during SSL write:");
    return false;
  }

  return true;
}


/**
 * Receive a string value.
 * @param s the string to fill.
 * @return true on success, false otherwise.
 */
bool 
GSISocketClient::Receive(std::string& s)
{
  if (!ssl) {
    SetError("No connection established");
    return false;
  }

  ERR_clear_error();

  int ret = -1, ret2 = -1;

  int bufsize=8192;

  char *buffer = (char *)OPENSSL_malloc(bufsize);

  int fd = BIO_get_fd(SSL_get_rbio(ssl), NULL);
  time_t starttime, curtime;

  fd_set rset;
  fd_set wset;
  int error = 0;
  int expected = 0;

  starttime = time(NULL);

  do {
    ret = do_select(fd, &rset, &wset, starttime, timeout, expected);
    curtime = time(NULL);

    if (ret > 0) {
      ret2 = SSL_read(ssl, buffer, bufsize);

      if (ret2 <= 0)
        expected = error = SSL_get_error(ssl, ret2);
    }
  } while ((ret > 0) && 
	   ((ret2 <= 0) && 
	    (((timeout == -1) ||
	      ((timeout != -1) && 
	       (curtime - starttime < timeout))) &&
	     ((error == SSL_ERROR_WANT_READ) ||
	      (error == SSL_ERROR_WANT_WRITE)))));
            
  if (ret <= 0 || ret2 <= 0) {
    if (timeout != -1 && (curtime - starttime <= timeout))
      SetError("Connection stuck during read: timeout reached.");
    else
      SetErrorOpenSSL("Error during SSL read:");
    OPENSSL_free(buffer);
    return false;
  }

  s = std::string(buffer, ret2);
  OPENSSL_free(buffer);
  return true;
}
