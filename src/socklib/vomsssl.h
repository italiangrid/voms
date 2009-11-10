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

#ifndef VOMS_VOMSSSL_H
#define VOMS_VOMSSSL_H

#include <openssl/ssl.h>
#include <openssl/x509_vfy.h>
#ifdef __cplusplus
extern "C" {
#endif
  extern int proxy_verify_callback_server(X509_STORE_CTX *ctx, void *empty);
  extern int proxy_verify_callback_client(int ok, X509_STORE_CTX *ctx);
  extern void setup_SSL_proxy_handler(SSL *ssl, char *cadir);
  extern void destroy_SSL_proxy_handler(SSL *);

#ifdef __cplusplus
}
#endif
#endif
