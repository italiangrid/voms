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

#include "config.h"

#include "openssl/ssl.h"
#include "openssl/err.h"
#include "openssl/bio.h"
#include "openssl/pem.h"
#include "openssl/x509.h"

#if SSLEAY_VERSION_NUMBER >= 0x0090581fL
#include "openssl/x509v3.h"
#endif

#include "openssl/stack.h"

typedef void *globus_gsi_callback_data_t;

typedef struct globus_l_gsi_cred_handle_s
{
    /** The credential's signed certificate */ 
    X509 *                              cert;
    /** The private key of the credential */
    EVP_PKEY *                          key;
    /** The chain of signing certificates */
    STACK_OF(X509) *                    cert_chain;
} globus_i_gsi_cred_handle_t;

typedef struct globus_l_gsi_cred_handle_s * 
                                        globus_gsi_cred_handle_t;

typedef struct gss2_cred_id_desc_struct {
    globus_gsi_cred_handle_t            cred_handle;
} gss2_cred_id_desc;

#if !defined(GLOBUS_INCLUDE_GLOBUS_THREAD)
typedef int globus_mutex_t;
#endif

typedef struct gss2_ctx_id_desc_struct{
    globus_mutex_t                      mutex;
    globus_gsi_callback_data_t          callback_data;
    gss2_cred_id_desc *                 peer_cred_handle;
} gss2_ctx_id_desc;

#ifndef GSSAPI_H_
typedef void * gss_cred_id_t;
typedef void * gss_ctx_id_t;
#endif

#endif /* VOMS_GSSAPI_COMPAT_H */
