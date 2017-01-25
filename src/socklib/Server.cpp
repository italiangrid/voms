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
#include <sys/time.h>
#include <fcntl.h>

#include <memory.h>
#include <time.h>
#include <stdio.h>
#include <netdb.h>
#include <assert.h>

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
#include "ssl_compat.h"
}

#include "ipv6sock.h"
#include "io.h"

#include "data.h"

/** This class header file. */
#include "Server.h"

static int globusf_read(BIO *b, char *out, int outl);
static int globusf_write(BIO *b, const char *in, int inl);

extern "C" {
extern int proxy_app_verify_callback(X509_STORE_CTX *ctx, UNUSED(void *empty));
}

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
  newopened(false), mustclose(m), logh(l), openssl_errors()
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
  error.clear();
  openssl_errors.clear();
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

static BIO* make_VOMS_BIO(int sock)
{
  int ret;

  int const biom_type = BIO_get_new_index();
  static char const* const biom_name = "VOMS I/O";
  BIO_METHOD* voms_biom = BIO_meth_new(biom_type|BIO_TYPE_SOURCE_SINK|BIO_TYPE_DESCRIPTOR, biom_name);
  assert(voms_biom && "BIO_meth_new failed");

  BIO_METHOD const* sock_biom = BIO_s_socket();
  assert(sock_biom != NULL && "BIO_s_socket");

  writeb = BIO_meth_get_write(const_cast<BIO_METHOD*>(sock_biom));
  assert(writeb != NULL && "BIO_meth_get_write failed");
  ret = BIO_meth_set_write(voms_biom, globusf_write);
  assert(ret == 1 && "BIO_meth_set_write failed");

  readb = BIO_meth_get_read(const_cast<BIO_METHOD*>(sock_biom));
  assert(readb != NULL && "BIO_meth_get_read failed");
  ret = BIO_meth_set_read(voms_biom, globusf_read);
  assert(ret == 1 && "BIO_meth_set_read failed");

  ret = BIO_meth_set_puts(
      voms_biom
    , BIO_meth_get_puts(const_cast<BIO_METHOD*>(sock_biom))
  );
  assert(ret == 1 && "BIO_meth_get/set_puts failed");

  ret = BIO_meth_set_gets(
      voms_biom
    , BIO_meth_get_gets(const_cast<BIO_METHOD*>(sock_biom))
  );
  assert(ret == 1 && "BIO_meth_get/set_gets failed");

  ret = BIO_meth_set_ctrl(
      voms_biom
    , BIO_meth_get_ctrl(const_cast<BIO_METHOD*>(sock_biom))
  );
  assert(ret == 1 && "BIO_meth_get/set_ctrl failed");

  ret = BIO_meth_set_create(
      voms_biom
    , BIO_meth_get_create(const_cast<BIO_METHOD*>(sock_biom))
  );
  assert(ret == 1 && "BIO_meth_get/set_create failed");

  ret = BIO_meth_set_destroy(
      voms_biom
    , BIO_meth_get_destroy(const_cast<BIO_METHOD*>(sock_biom))
  );
  assert(ret == 1 && "BIO_meth_get/set_destroy failed");

  ret = BIO_meth_set_callback_ctrl(
      voms_biom
    , BIO_meth_get_callback_ctrl(const_cast<BIO_METHOD*>(sock_biom))
  );
  assert(ret == 1 && "BIO_meth_get/set_callback_ctrl failed");

  BIO* voms_bio = BIO_new(voms_biom);
  assert(voms_bio && "BIO_new failed");
  BIO_set_fd(voms_bio, sock, BIO_NOCLOSE);
  (void)BIO_set_nbio(voms_bio, 1);

  return voms_bio;
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
  int ret, accept_status;
  bool accept_timed_out = false;
  int expected = 0;
  BIO *bio = NULL;
  BIO_METHOD* bio_method = NULL;
  char *cert_file, *user_cert, *user_key, *user_proxy;
  char *serial=NULL;

  cert_file = user_cert = user_key = user_proxy = NULL;

  if (proxy_get_filenames(0, &cert_file, &cacertdir, &user_proxy, &user_cert, &user_key) == 0) 
  {
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
    X509_STORE_add_cert(SSL_CTX_get_cert_store(ctx), ucert);
    for (int i = 0; i <sk_X509_num(own_stack); ++i) {
      X509 *cert = (sk_X509_value(own_stack,i));

      if (!X509_STORE_add_cert(SSL_CTX_get_cert_store(ctx), cert)) {
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

  bio = make_VOMS_BIO(newsock);

  ssl = SSL_new(ctx);
  setup_SSL_proxy_handler(ssl, cacertdir);

  SSL_set_bio(ssl, bio, bio);

  curtime = starttime = time(NULL);

  ret = accept_status = -1;
  expected = 0;

  LOGM(VARP, logh, LEV_DEBUG, T_PRE, "Handshake timeout: %d", timeout);

  do {

    ret = do_select(newsock, starttime, timeout, expected);
    curtime = time(NULL);

    if (ret == 0){

      if ((timeout != -1) && (curtime - starttime >= timeout)){

        LOGM(VARP, logh, LEV_DEBUG, T_PRE, "Socket timed out. Failing the handshake.");
        accept_timed_out = true;
        break;

      }else{

        LOGM(VARP, logh, LEV_DEBUG, T_PRE, "Socket timed out, but global timeout still not reached. Continuing...");
        continue;
      }
      
    }
    
    if (ret > 0) 
    {
      accept_status = SSL_accept(ssl);
      expected = errorcode = SSL_get_error(ssl, accept_status);
    }

    if (ret < 0)
    {
      LOGM(VARP, logh, LEV_DEBUG, T_PRE, "No more data from select.");
      break;
    }

    if (accept_status == 1)
    {
      LOGM(VARP, logh, LEV_DEBUG, T_PRE, "SSL accept completed.");
      break;
    }

    curtime = time(NULL);

    if (timeout != -1 && (curtime - starttime >= timeout))
    {
      accept_timed_out = true;
      LOGM(VARP, logh, LEV_DEBUG, T_PRE, "Handshake timeout.");
      break;
    }

    if (accept_status <= 0 && ( errorcode != SSL_ERROR_WANT_READ && errorcode != SSL_ERROR_WANT_WRITE ))
    {
      break;
    }
    
  } while (true);
  
  if (accept_status != 1){

    LOGM(VARP, logh, LEV_INFO, T_PRE, "Error enstabilishing SSL context.");

    if (accept_timed_out){
      SetError("SSL Handshake failed due to server timeout!");
    }else{
      SetErrorOpenSSL("SSL Handshake error");
    }

    goto err;
  }
  
  actual_cert = SSL_get_peer_certificate(ssl);
  peer_stack  = SSL_get_peer_cert_chain(ssl);

  char buffer[1000];

  LOGM(VARP, logh, LEV_DEBUG, T_PRE, "Certificate DN: %s",
      X509_NAME_oneline(X509_get_subject_name(actual_cert), buffer, 999));

  LOGM(VARP, logh, LEV_DEBUG, T_PRE, "Certificate CA: %s",
      X509_NAME_oneline(X509_get_issuer_name(actual_cert), buffer, 999));

  LOGM(VARP, logh, LEV_DEBUG, T_PRE, "Stack Size: %d", sk_X509_num(peer_stack));

  peer_cert = get_real_cert(actual_cert, peer_stack);

  if (!peer_cert) 
  {
    LOGM(VARP, logh, LEV_INFO, T_PRE, "No end user certificate found for peer...");
    goto err;
  }

  if (!peer_stack)
  {
    LOGM(VARP, logh, LEV_INFO, T_PRE, "No certificate stack found for peer. Exiting...");
    goto err;
  }

  if (peer_cert) 
  {
    char* name = X509_NAME_oneline(X509_get_subject_name(peer_cert), NULL, 0);

    if (!name)
    {
      LOGM(VARP, logh, LEV_INFO, T_PRE, "Could not fetch name from peer cert. Exiting...");
      goto err;
    }

    own_subject = std::string(name);
    OPENSSL_free(name);
  }

  if (LogLevelMin(logh, LEV_DEBUG))
  {
    for (int i = 0; i < sk_X509_num(peer_stack); i++) 
    {
      X509 *cert = sk_X509_value(peer_stack, i);
      
      if (cert) 
      {
        LOGM(VARP, logh, LEV_DEBUG, T_PRE, "Certificate DN: %s",
            X509_NAME_oneline(X509_get_subject_name(cert), buffer, 999));

        LOGM(VARP, logh, LEV_DEBUG, T_PRE, "Certificate CA: %s",
            X509_NAME_oneline(X509_get_issuer_name(cert), buffer, 999));
      }
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

  OPENSSL_free(serial);

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
    if (timeout != -1 && (curtime - starttime >= timeout))
      SetError("Connection stuck during read: timeout reached.");
    else
      SetErrorOpenSSL("Error during SSL read");
    OPENSSL_free(buffer);
    ERR_clear_error();
    return false;
  }

  s = std::string(buffer, ret2);
  OPENSSL_free(buffer);
  ERR_clear_error();
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

  ERR_clear_error();

  return result;
}

void GSISocketServer::SetError(const std::string &g)
{
  error = g;
  openssl_errors.clear();
}

void GSISocketServer::SetErrorOpenSSL(const std::string &err)
{
  error = err;
  openssl_errors.clear();

  while( ERR_peek_error() ){

    char error_msg_buf[512];

    const char *filename;
    int lineno;
    const char* data;
    int flags;

    long error_code = ERR_get_error_line_data(&filename, &lineno, &data, &flags);

    const char *lib = ERR_lib_error_string(error_code);
    const char *func = ERR_func_error_string(error_code);
    const char *error_reason = ERR_reason_error_string(error_code);

    if (lib == NULL) {

      int lib_no = ERR_GET_LIB(error_code);

      if (lib_no == ERR_USER_LIB_PRXYERR_NUMBER){
        lib = "VOMS proxy routines";
      }
    }

    sprintf(error_msg_buf,
        "%s %s [err:%lu,lib:%s,func:%s(file: %s+%d)]",
        (error_reason) ? error_reason : "",
        (data) ? data : "",
        error_code,lib,func,filename,lineno);

    openssl_errors.push_back(error_msg_buf);
  }
}

const std::vector<std::string>&
GSISocketServer::GetOpenSSLErrors(){

  return openssl_errors;
}
