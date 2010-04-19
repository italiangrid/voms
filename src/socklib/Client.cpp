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

#include "sslutils.h"
}

#include "ipv6sock.h"
#include "io.h"

#include <cstring>
#include "data.h"

/** This class header file. */
#include "Client.h"

/**
 * Constructor.
 * @param p the secure server port.
 * @param b the backlog, that is the maximum number of outstanding connection requests.
 */
GSISocketClient::GSISocketClient(const std::string &h, int p) :
  host(h), port(p),
  opened(false), own_subject(""),
  upkey(NULL), ucert(NULL), cacertdir(NULL),
  ssl(NULL), ctx(NULL),
  conn(NULL), error(""), timeout(-1)
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

  error += OpenSSLError(true);
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

void destroy_initializers(void *data) 
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


/**
 * Open the connection.
 * @return true for successful opening, false otherwise.
 */
bool 
GSISocketClient::Open()
{
  SSL_METHOD *meth = NULL;
  int fd = -1;
  char portstring[36];
  int flags;
  std::string error;

  meth = SSLv3_method();

  ctx = SSL_CTX_new(meth);

  if (!ctx) {
    SetErrorOpenSSL("Cannot create context.");
    goto err;
  }

  SSL_CTX_set_options(ctx, SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS | SSL_OP_NO_TLSv1 | SSL_OP_NO_SSLv2);
  SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, proxy_verify_callback);
  SSL_CTX_set_verify_depth(ctx, 100);
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

  snprintf(portstring, 35, "%ld", (long int)port);
  fd = sock_connect(host.c_str(), portstring);

  if (fd != -1) {
    flags = fcntl(fd, F_GETFL, 0);
    (void)fcntl(fd, F_SETFL, flags | O_NONBLOCK);

    conn = BIO_new_socket(fd, BIO_NOCLOSE);
    (void)BIO_set_nbio(conn,1);

    ssl = SSL_new(ctx);
    setup_SSL_proxy_handler(ssl, cacertdir);
    SSL_set_bio(ssl, conn, conn);

    conn = NULL;

    if (!do_connect(ssl, fd, timeout, error)) {
      SetError(error);
      goto err;
    }

    if (post_connection_check(ssl)) {
      opened = true;
      (void)Send("0");
      return true;
    }
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
    upkey = NULL;
    ucert = NULL;
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
  std::string error;

  bool result = do_write(ssl, timeout, s, error);

  if (!result)
    SetError(error);

  return result;
}


/**
 * Receive a string value.
 * @param s the string to fill.
 * @return true on success, false otherwise.
 */
bool 
GSISocketClient::Receive(std::string& s)
{
  std::string output;
  bool result = do_read(ssl, timeout, output);

  if (result)
    s = output;
  else
    SetError(output);

  return result;
}
