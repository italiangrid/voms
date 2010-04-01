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
#include <fcntl.h>

#include <memory.h>
#include <time.h>
#include <stdio.h>
#include <netdb.h>

#include <openssl/evp.h>
#include <openssl/buffer.h>
#include <openssl/crypto.h>
#include <openssl/objects.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include "credentials.h"
#include "log.h"
#include "vomsssl.h"
#include "sslutils.h"
}

#include "ipv6sock.h"
#include "io.h"

#include "data.h"

/** This class header file. */
#include "Server.h"

static int globusf_read(BIO *b, char *out, int outl);
static int globusf_write(BIO *b, const char *in, int inl);

typedef enum { UNKNOWN, GSI, SSL2, TLS, SSL_GLOBUS} mode_type;

static mode_type mode = UNKNOWN; /* Global, since it needs to be shared between 
                                    send and receive. */
static int expected = 0;

static mode_type detect_mode(unsigned char *beginning) 
{
  if (beginning[0] >= 20 && beginning[0] <= 23) {
    /*
     * either TLS or SSL3.  They are equivalent for our purposes.
     */
    return TLS;
  }

  if (beginning[0] == 26)
    return SSL_GLOBUS; /* Globus' own SSL variant */

  if (beginning[0] & 0x80) {
  /*
   * The data length of an SSL packet is at most 32767.
   */
    return SSL2;
  }

#if 0
  if (beginning[0] & 0xc0)
    return SSL2;
#endif

  return GSI;
}

int (*readb)(BIO *, char *, int);
int (*writeb)(BIO *, const char *, int);

static int globusf_read(BIO *b, char *out, int outl)
{
  int ret = 0;

  ret = readb(b, out, outl);

  if (ret >= 4) {
    if (mode == UNKNOWN)
      mode = detect_mode((unsigned char*)out);

    if (mode == GSI) {
      if (expected == 0) {
        expected = ((((((unsigned char)out[0] << 8) + 
                       (unsigned char)out[1]) << 8) + 
                     (unsigned char)out[2]) << 8) + 
          (unsigned char)out[3];
        memmove(out, out + 4, ret - 4);
        ret -= 4;
      }
      expected -= ret;

      if (ret == 0) {
        // implies only size was read.  Better reread.
        ret = readb(b, out, outl);

        if (ret > 0) {
          expected -= ret;
        }
      }
    }
  }
  else if (ret > 0) {
    if ((mode == GSI) && (expected > 0))
      expected -= ret;
  }

  return ret;
}

static int globusf_write(BIO *b, const char *in, int inl) 
{
  int ret = 0;

  if (mode != GSI) 
    ret = writeb(b, in, inl);
  else {
    unsigned char buffer[4];
    buffer[0] = (inl & 0xff000000) >> 24;
    buffer[1] = (inl & 0x00ff0000) >> 16;
    buffer[2] = (inl & 0x0000ff00) >> 8;
    buffer[3] = (inl & 0x000000ff);
    writeb(b, (const char*)(buffer), 4);
    ret = writeb(b, in, inl);
  }

  return ret;
}

/**
 * Constructor.
 * @param p the secure server port.
 * @param b the backlog, that is the maximum number of outstanding connection requests.
 */
GSISocketServer::GSISocketServer(int p, void *l, int b, bool m) :
  own_subject(""), own_ca(""), peer_subject(""), 
  peer_ca(""), peer_serial(""), own_key(NULL), own_cert(NULL), 
  peer_cert(NULL), own_stack(NULL), peer_stack(NULL), 
  ssl(NULL), ctx(NULL), conn(NULL), pvd(NULL), cacertdir(NULL),
  upkey(NULL), ucert(NULL), error(""),
  port(p), opened(false), sck(-1), backlog(b), newsock(-1), timeout(30),
  newopened(false), mustclose(m), logh(l)
{
  if (OBJ_txt2nid("UID") == NID_undef)
    OBJ_create("0.9.2342.19200300.100.1.1","USERID","userId");
}

void GSISocketServer::SetTimeout(int sec)
{
  timeout = sec;
}

bool
GSISocketServer::ReOpen(int p, int b, bool m)
{
  Close();
  port = p;
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
  char portstring[36];

  snprintf(portstring, 35, "%ld", (long int)port);
  sck = bind_and_listen(portstring, backlog, logh);

  return sck != -1;
}

void GSISocketServer::AdjustBacklog(int n)
{
  backlog = n;
  listen(sck, n);
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

    setsockopt(newsock, SOL_SOCKET, SO_LINGER, (void *)&l, sizeof(struct linger));
  }
}

/**
 * Close the connection.
 */
void 
GSISocketServer::Close()
{
  if (newopened) {
    close(newsock);
  }
  newopened=false;

  if (opened)
    close(sck);
  opened = false;

  own_key = NULL;
  own_cert = peer_cert = NULL;

  opened=false;
}

void GSISocketServer::CloseListener(void)
{
  if (opened) {
    struct linger l = {1,0};

    setsockopt(sck, SOL_SOCKET, SO_LINGER, (void *)&l, sizeof(struct linger));

    close(sck);
  }
  opened = false;
}

void GSISocketServer::CloseListened(void)
{
  if (newopened)
    close(newsock);
  newopened = false;
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
  char *name = NULL;
  long  errorcode = 0;
  int   flags;

  time_t curtime, starttime;
  int ret, ret2;
  int expected = 0;
  BIO *bio = NULL;
  char *cert_file, *user_cert, *user_key, *user_proxy;
  char *serial=NULL;

  cert_file = user_cert = user_key = user_proxy = NULL;

  if (proxy_get_filenames(0, &cert_file, &cacertdir, &user_proxy, &user_cert, &user_key) == 0) {
    (void)load_credentials(user_cert, user_key, &ucert, &own_stack, &upkey, NULL);
  }

  free(cert_file);
  free(user_cert);
  free(user_key);
  free(user_proxy);

  own_cert = ucert;
  own_key = upkey;
  ctx = SSL_CTX_new(SSLv23_method());
  SSL_CTX_load_verify_locations(ctx, NULL, cacertdir);
  SSL_CTX_use_certificate(ctx, ucert);
  SSL_CTX_use_PrivateKey(ctx,upkey);
  SSL_CTX_set_cipher_list(ctx, "ALL:!LOW:!EXP:!MD5:!MD2");    
  SSL_CTX_set_purpose(ctx, X509_PURPOSE_ANY);
  SSL_CTX_set_mode(ctx, SSL_MODE_AUTO_RETRY);
  SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, proxy_verify_callback);
  SSL_CTX_set_verify_depth(ctx, 100);
  SSL_CTX_set_cert_verify_callback(ctx, proxy_app_verify_callback, 0);

  if (own_stack) {
    /*
     * Certificate was a proxy with a cert. chain.
     * Add the certificates one by one to the chain.
     */
    X509_STORE_add_cert(ctx->cert_store, ucert);
    for (int i = 0; i <sk_X509_num(own_stack); ++i) {
      X509 *cert = (sk_X509_value(own_stack,i));

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

  flags = fcntl(newsock, F_GETFL, 0);
  (void)fcntl(newsock, F_SETFL, flags | O_NONBLOCK);

  bio = BIO_new_socket(newsock, BIO_NOCLOSE);
  (void)BIO_set_nbio(bio, 1);

  ssl = SSL_new(ctx);
  setup_SSL_proxy_handler(ssl, cacertdir);

  writeb = bio->method->bwrite;
  readb  = bio->method->bread;
  bio->method->bwrite = globusf_write;
  bio->method->bread  = globusf_read;

  SSL_set_bio(ssl, bio, bio);

  curtime = starttime = time(NULL);

  ret = ret2 = -1;
  expected = 0;

  do {
    ret = do_select(newsock, starttime, timeout, expected);
    if (ret > 0) {
      ret2 = SSL_accept(ssl);
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


  actual_cert = SSL_get_peer_certificate(ssl);
  peer_stack  = SSL_get_peer_cert_chain(ssl);

  char buffer[1000];

  if (LogLevelMin(logh, LEV_DEBUG)) {
      LOGM(VARP, logh, LEV_DEBUG, T_PRE, "Certificate DN: %s",
           X509_NAME_oneline(X509_get_subject_name(actual_cert), buffer, 999));
      LOGM(VARP, logh, LEV_DEBUG, T_PRE, "Certificate CA: %s",
           X509_NAME_oneline(X509_get_issuer_name(actual_cert), buffer, 999));
      LOGM(VARP, logh, LEV_DEBUG, T_PRE, "Stack Size: %d", sk_X509_num(peer_stack));
  }

  peer_cert = get_real_cert(actual_cert, peer_stack);

  if (peer_cert) {
    char *name = X509_NAME_oneline(X509_get_subject_name(peer_cert), NULL, 0);
    own_subject = std::string(name);
    OPENSSL_free(name);
  }

  if (LogLevelMin(logh, LEV_DEBUG)) {
    for (int i = 0; i < sk_X509_num(peer_stack); i++) {
      X509 *cert = sk_X509_value(peer_stack, i);
      LOGM(VARP, logh, LEV_DEBUG, T_PRE, "Certificate DN: %s",
           X509_NAME_oneline(X509_get_subject_name(cert), buffer, 999));
      LOGM(VARP, logh, LEV_DEBUG, T_PRE, "Certificate CA: %s",
           X509_NAME_oneline(X509_get_issuer_name(cert), buffer, 999));
    }
  }

  name = X509_NAME_oneline(X509_get_subject_name(peer_cert), NULL, 0);
  if (name)
    peer_subject = std::string(name); 
  OPENSSL_free(name);

  name = X509_NAME_oneline(X509_get_issuer_name(peer_cert), NULL, 0);
  if (name)
    peer_ca = std::string(name);
  OPENSSL_free(name);

  serial = get_peer_serial(actual_cert);
  peer_serial = std::string(serial ? serial : "");
  free(serial);

  return true;

err:
  destroy_SSL_proxy_handler(ssl);
  SSL_free(ssl);
  SSL_CTX_free(ctx);

  return false;
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
  newsock = accept_ipv6(sck, logh);

  if (newsock != -1)
    newopened = true;

  return newsock != -1;
}

/**
 * Send a string value.
 * @param s the string value to send.
 * @return true on success, false otherwise.
 */ 
bool 
GSISocketServer::Send(const std::string &s)
{
  std::string error;

  bool result = do_write(ssl, timeout, s, error);

  if (!result)
    SetError(error);

  return result;
}

bool GSISocketServer::Peek(int bufsize, std::string& s)
{
  if (!ssl) {
    SetError("No connection established");
    return false;
  }

  ERR_clear_error();

  int ret = -1, ret2 = -1;

  char *buffer = (char *)OPENSSL_malloc(bufsize);

  int fd = BIO_get_fd(SSL_get_rbio(ssl), NULL);
  time_t starttime, curtime;

  int error = 0;
  int expected = 0;

  starttime = time(NULL);

  do {
    ret = do_select(fd, starttime, timeout, expected);
    curtime = time(NULL);

    if (ret > 0) {
      ret2 = SSL_peek(ssl, buffer, bufsize);

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

/**
 * Receive a string value.
 * @param s the string to fill.
 * @return true on success, false otherwise.
 */
bool 
GSISocketServer::Receive(std::string& s)
{
  std::string output;
  bool result = do_read(ssl, timeout, output);

  if (result)
    s = output;
  else
    SetError(output);

  return result;
}

void GSISocketServer::SetError(const std::string &g)
{
  error = g;
}

void GSISocketServer::SetErrorOpenSSL(const std::string &message)
{
  error = message;

  error += OpenSSLError(true);
}

