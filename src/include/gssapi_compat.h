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

/**********************************************************************
gssapi_ssleay.h:

Description:
        This header file used internally by the gssapi_ssleay
        routines

**********************************************************************/

#ifndef VOMS_GSSAPI_COMPAT_H
#define VOMS_GSSAPI_COMPAT_H

/**********************************************************************
                             Include header files
**********************************************************************/

#include "gssapi.h"
#include "sslutils.h"
#include <stdio.h>
#include "openssl/ssl.h"
#include "openssl/err.h"
#include "openssl/bio.h"
#include "openssl/pem.h"
#include "openssl/x509.h"

#if SSLEAY_VERSION_NUMBER >= 0x0090581fL
#include "openssl/x509v3.h"
#endif

#include "openssl/stack.h"

#if defined(WIN32)
#   include "windows.h"
#endif

typedef struct globus_l_gsi_callback_data_s *
                                        globus_gsi_callback_data_t;

typedef struct globus_l_gsi_proxy_handle_s * 
                                        globus_gsi_proxy_handle_t;

typedef enum
{
    GS_CON_ST_HANDSHAKE = 0,
    GS_CON_ST_FLAGS,
    GS_CON_ST_REQ,
    GS_CON_ST_CERT,
    GS_CON_ST_DONE
}
gs_con_st_t;

typedef enum
{
    GS_DELEGATION_START,
    GS_DELEGATION_DONE,
    GS_DELEGATION_COMPLETE_CRED,
    GS_DELEGATION_SIGN_CERT
}
gs_delegation_state_t;

typedef struct gss_name_desc_struct
{
    /* gss_buffer_desc  name_buffer ; */
    gss_OID name_oid;
    X509_NAME *x509n;
}
gss_name_desc;

typedef struct gss_cred_id_desc_struct
{
    proxy_cred_desc *pcd;
    gss_name_desc *globusid;
    gss_cred_usage_t cred_usage;
    BIO *gs_bio_err;
}
gss_cred_id_desc;

typedef struct gss_ctx_id_desc_struct
{
    proxy_verify_desc pvd;	/* used for verify_callback */
    proxy_verify_ctx_desc pvxd;
    gss_name_desc *source_name;
    gss_name_desc *target_name;
    gss_cred_id_desc *cred_handle;
    OM_uint32 ret_flags;
    OM_uint32 req_flags;
    OM_uint32 ctx_flags;
    int cred_obtained;
    SSL *gs_ssl;
    BIO *gs_rbio;
    BIO *gs_wbio;
    BIO *gs_sslbio;
    gs_con_st_t gs_state;
    int locally_initiated;
    time_t goodtill;
    /* following used during delegation */

    /* new key for delegated proxy - do we need this now that we have
     * init/accept-delegation
     */
    EVP_PKEY *dpkey;
    /* delegated cert */
    X509 *dcert;
    /* delegation state */
    gs_delegation_state_t delegation_state;
}
gss_ctx_id_desc;


typedef enum {
    GSS_CON_ST_HANDSHAKE = 0,
    GSS_CON_ST_FLAGS,
    GSS_CON_ST_REQ,
    GSS_CON_ST_CERT,
    GSS_CON_ST_DONE
} gss_con_st_t;

typedef enum
{
    GSS_DELEGATION_START,
    GSS_DELEGATION_DONE,
    GSS_DELEGATION_COMPLETE_CRED,
    GSS_DELEGATION_SIGN_CERT
} gss_delegation_state_t;

typedef enum 
{
    GLOBUS_PROXY,
    GLOBUS_USER,
    GLOBUS_HOST,
    GLOBUS_SERVICE,
    GLOBUS_SO_END
} globus_gsi_cred_type_t;

typedef struct globus_l_gsi_cred_handle_attrs_s
{
    /* the filename of the CA certificate directory */
    char *                              ca_cert_dir;
    /* the order to search in for a certificate */
    globus_gsi_cred_type_t *            search_order; /*{PROXY,USER,HOST}*/
} globus_i_gsi_cred_handle_attrs_t;


typedef struct globus_l_gsi_cred_handle_attrs_s *
                                        globus_gsi_cred_handle_attrs_t;

typedef struct globus_l_gsi_cred_handle_s
{
    /** The credential's signed certificate */ 
    X509 *                              cert;
    /** The private key of the credential */
    EVP_PKEY *                          key;
    /** The chain of signing certificates */
    STACK_OF(X509) *                    cert_chain;
    /** The immutable attributes of the credential handle */
    globus_gsi_cred_handle_attrs_t      attrs;
    /** The amout of time the credential is valid for */
    time_t                              goodtill;
} globus_i_gsi_cred_handle_t;

typedef struct globus_l_gsi_cred_handle_s * 
                                        globus_gsi_cred_handle_t;

typedef struct gss2_name_desc_struct {
    /* gss_buffer_desc  name_buffer ; */
    gss_OID                             name_oid;
    X509_NAME *                         x509n;
    STACK *                             group;
    ASN1_BIT_STRING *                   group_types;
} gss2_name_desc;

typedef struct gss2_cred_id_desc_struct {
    globus_gsi_cred_handle_t            cred_handle;
    gss2_name_desc *                     globusid;
    gss_cred_usage_t                    cred_usage;
    SSL_CTX *                           ssl_context;
} gss2_cred_id_desc;

#if !defined(GLOBUS_INCLUDE_GLOBUS_THREAD)
typedef int globus_mutex_t;
#endif

typedef struct gss2_ctx_id_desc_struct{
    globus_mutex_t                      mutex;
    globus_gsi_callback_data_t          callback_data;
    gss2_cred_id_desc *                 peer_cred_handle;
    gss2_cred_id_desc *                 cred_handle;
    gss2_cred_id_desc *                 deleg_cred_handle;
    globus_gsi_proxy_handle_t           proxy_handle;
    OM_uint32                           ret_flags;
    OM_uint32                           req_flags;
    OM_uint32                           ctx_flags;
    int                                 cred_obtained;
    SSL *                               gss_ssl; 
    BIO *                               gss_rbio;
    BIO *                               gss_wbio;
    BIO *                               gss_sslbio;
    gss_con_st_t                        gss_state;
    int                                 locally_initiated;
    gss_delegation_state_t              delegation_state;
} gss2_ctx_id_desc;

#endif /* _GSSAPI_COMPAT_H */
