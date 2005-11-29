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

#include "gssapi.h"
#include "globus_gss_assist.h"

#include <openssl/x509.h>
#include <openssl/evp.h>

extern int globus(int);
extern X509 *get_own_cert(void);
extern X509 *decouple_cred(gss_cred_id_t credential, int version, STACK_OF(X509) **stk);
extern X509 *decouple_ctx(gss_ctx_id_t context, int version, STACK_OF(X509) **stk);
extern X509 *get_real_cert(X509 *base, STACK_OF(X509) *stk);
extern EVP_PKEY *get_delegated_public_key(gss_ctx_id_t context, int globusver);
extern int get_issuer(X509 *cert, char **buffer);
extern EVP_PKEY *get_private_key(void *credential, int globusver);
extern int get_own_data(gss_cred_id_t credential, int globusver, EVP_PKEY **key, char **issuer, X509 **pcert);
extern int get_peer_data(gss_ctx_id_t context, int globusver, EVP_PKEY **key, char **issuer, X509 **pcert);
extern char *get_globusid(gss_cred_id_t handle);
extern char *get_peer_serial(X509 *);

#endif
