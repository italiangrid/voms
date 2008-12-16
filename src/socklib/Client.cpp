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
#include <openssl/ssl.h>
#include <openssl/x509v3.h>
#include <openssl/err.h>
#include <openssl/bio.h>

#include "log.h"
  //#include "globuswrap.h"
#include "sslutils.h"
}

#include "data.h"

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
  host(h), port(p), version(v), context(0L),
  credential(0L), _server_contact(""), conflags(0),
  opened(false), own_subject(""), own_ca(""),
  upkey(NULL), ucert(NULL), cacertdir(NULL),
  peer_subject(""), peer_ca(""), 
  peer_key(NULL), peer_cert(NULL), logh(l), ssl(NULL), ctx(NULL),
  conn(NULL), pvd(NULL), error("")
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
GSISocketClient::SetFlags(int f)
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
      dat = (char*)"";
    else
      dat = es->err_data[i];
    if (dat) {
      l = ERR_get_error_line(&file, &line);
      //      if (debug)
      std::string temp;
      error += std::string(ERR_error_string(l, buf)) + ":" + std::string(file) + ":" +
        stringify(line, temp) + ":" + std::string(dat) + "\n";
        //      else
      error += std::string(ERR_reason_error_string(l)) + ":" + std::string(ERR_func_error_string(l)) + "\n";
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

  //  peer_subject = _server_contact.empty() ? "" : _server_contact; 
  //  get_peer_data(context, version, &peer_key, &tmp, &peer_cert);
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


// extern "C" {
// extern int proxy_app_verify_callback(X509_STORE_CTX *, void *);
// }


static proxy_verify_desc *setup_initializers() 
{
  proxy_verify_ctx_desc *pvxd = NULL;
  proxy_verify_desc *pvd = NULL;

  pvd  = (proxy_verify_desc*)     malloc(sizeof(proxy_verify_desc));
  pvxd = (proxy_verify_ctx_desc *)malloc(sizeof(proxy_verify_ctx_desc));

  if (!pvd || !pvxd) {
    free(pvd);
    free(pvxd);
    return NULL;
  }

  proxy_verify_ctx_init(pvxd);
  proxy_verify_init(pvd, pvxd);

  return pvd;

}

static void destroy_initializers(proxy_verify_desc *pvd) 
{
  if (pvd) {
    if (pvd->pvxd)
      proxy_verify_ctx_release(pvd->pvxd);
    free(pvd->pvxd);
    proxy_verify_release(pvd);
    free(pvd);
  }
}

/**
 * Open the connection.
 * @return true for successful opening, false otherwise.
 */
bool 
GSISocketClient::Open()
{
  SSL_METHOD *meth = NULL;

  meth = SSLv3_method();

  ctx = SSL_CTX_new(meth);

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
  
  std::string hostport;
  std::string temp;

  if (cert_chain) {
    /*
     * Certificate was a proxy with a cert. chain.
     * Add the certificates one by one to the chain.
     */
    for (int i = 0; i <sk_X509_num(cert_chain); ++i) {
      //      X509 *cert = X509_dup(sk_X509_value(cert_chain,i));
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


  hostport = host + ":" + stringify(port,temp);

  conn = BIO_new_connect((char*)hostport.c_str());

  if (BIO_do_connect(conn) <= 0) {
    goto err;
  }

  ssl = SSL_new(ctx);
  pvd = setup_initializers();
  pvd->pvxd->certdir = cacertdir;

  SSL_set_ex_data(ssl, PVD_SSL_EX_DATA_IDX, pvd);
  SSL_set_bio(ssl, conn, conn);
  conn = NULL;
  if (SSL_connect(ssl) <= 0) {
    goto err;
  }

  if (post_connection_check(ssl)) {
    opened = true;
    return true;
  }

 err:
  SSL_free(ssl);
  SSL_CTX_free(ctx);
  BIO_free(conn);
  destroy_initializers(pvd);

  return false;
}
  

/**
 * Close the connection.
 * @return true for successful close, false otherwise.
 */
void
GSISocketClient::Close()
{
  int status = 0;

  if (opened) {
    context = 0L;
    credential = 0L;

    if (peer_key) 
      EVP_PKEY_free(peer_key);
    peer_key = upkey = NULL;
    peer_cert = ucert = NULL;
    cert_chain = NULL;

    //    SSL_shutdown(ssl);
    SSL_clear(ssl);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    BIO_free(conn);
    destroy_initializers(pvd);

    opened=false;
  }
}


/**
 * Send a string value.
 * @param s the string value to send.
 * @return true on success, false otherwise.
 */ 
bool 
GSISocketClient::Send(const std::string s)
{
  if (!ssl) {
    SetError("No connection established");
    return false;
  }

  ERR_clear_error();

  int size=0, nwritten=0;

  const char *str = s.c_str();


  for (nwritten = 0; nwritten < s.length(); nwritten += size) {
    size = SSL_write(ssl, str + nwritten, strlen(str) - nwritten);

    if (size <= 0) {
      SetErrorOpenSSL("");
      return false;
    }
    else
      nwritten += size;     
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

  int size, nread;

  int bufsize=8192;

  char *buffer = (char *)OPENSSL_malloc(bufsize);


  do {
    size = SSL_read(ssl, buffer, bufsize);
    if (size <= 0) {
      if (size == SSL_ERROR_WANT_READ)
        continue;
      else
        break;
    }
  } while (size == 0);

  if (size == 0) {
    free(buffer);
    return false;
  }

  s = std::string(buffer, size);
  OPENSSL_free(buffer);
  return true;
}
