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
#ifndef VOMS_NEWCA_H
#define VMS_NEWCA_H

extern "C" {
#include <openssl/x509.h>
#include <openssl/evp.h>

/* newca.c */
extern char *get_peer_CA(gss_ctx_id_t context, int globusver);
extern char *getMCA(void *credential, int version);
extern EVP_PKEY *get_private_key(void *credential, int globusver);
extern EVP_PKEY *get_delegated_public_key(gss_ctx_id_t context, int globusver);
extern X509 *get_peer_cert(gss_ctx_id_t contex, int globusver);
extern int   get_peer_data(gss_ctx_id_t, int, EVP_PKEY **, char **, X509 **);
extern int   get_own_data(gss_ctx_id_t, int, EVP_PKEY **, char **, X509 **);
};

#endif
