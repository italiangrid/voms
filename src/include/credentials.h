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

#ifndef VOMS_CREDENTIALS_H
#define VOMS_CREDENTIALS_H

#include <openssl/x509.h>
#include <openssl/evp.h>

#include "gssapi_compat.h"

extern int globus(int);
extern X509 *get_real_cert(X509 *base, STACK_OF(X509) *stk);
extern int get_issuer(X509 *cert, char **buffer);
extern EVP_PKEY *get_private_key(void *credential);
extern char *get_peer_serial(X509 *);

extern X509 *decouple_cred(gss_cred_id_t credential, STACK_OF(X509) **stk);
extern EVP_PKEY *get_delegated_public_key(gss_ctx_id_t context, int globusver);
extern int get_own_data(gss_cred_id_t credential, EVP_PKEY **key, char **issuer, X509 **pcert);

X509 *
load_cert_name(const char *filename, STACK_OF(X509) **stack, EVP_PKEY **key);

#endif
