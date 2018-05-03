/*********************************************************************
 *
 * Authors: Vincenzo Ciaschini - Vincenzo.Ciaschini@cnaf.infn.it 
 *          Valerio Venturi    - Valerio.Venturi@cnaf.infn.it
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
sslutils.h:

Description:
        This header file used internally by the gssapi_ssleay
        routines

**********************************************************************/

#ifndef VOMS_SSLUTILS_H
#define VOMS_SSLUTILS_H

#ifndef EXTERN_C_BEGIN
#ifdef __cplusplus
#define EXTERN_C_BEGIN extern "C" {
#define EXTERN_C_END }
#else
#define EXTERN_C_BEGIN
#define EXTERN_C_END
#endif
#endif

EXTERN_C_BEGIN

/**********************************************************************
                             Include header files
**********************************************************************/
#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "openssl/crypto.h"



#if SSLEAY_VERSION_NUMBER < 0x0090581fL
#define RAND_add(a,b,c) RAND_seed(a,b)
#define RAND_status() 1
#endif

#if SSLEAY_VERSION_NUMBER >= 0x00904100L
/* Support both OpenSSL 0.9.4 and SSLeay 0.9.0 */
#define OPENSSL_PEM_CB(A,B)  A, B
#else
#define RAND_add(a,b,c) RAND_seed(a,b)
#define OPENSSL_PEM_CB(A,B)  A

#define STACK_OF(A) STACK

#define sk_X509_num  sk_num
#define sk_X509_value  (X509 *)sk_value
#define sk_X509_push(A, B) sk_push(A, (char *) B)
#define sk_X509_insert(A,B,C)  sk_insert(A, (char *) B, C)
#define sk_X509_delete  sk_delete
#define sk_X509_new_null sk_new_null
#define sk_X509_pop_free sk_pop_free

#define sk_X509_NAME_ENTRY_num  sk_num
#define sk_X509_NAME_ENTRY_value  (X509_NAME_ENTRY *)sk_value

#define sk_SSL_CIPHER_num  sk_num
#define sk_SSL_CIPHER_value  (SSL_CIPHER*)sk_value
#define sk_SSL_CIPHER_insert(A,B,C)  sk_insert(A, (char *) B, C)
#define sk_SSL_CIPHER_delete  sk_delete
#define sk_SSL_CIPHER_push(A, B) sk_push(A, (char *) B)
#define sk_SSL_CIPHER_shift(A) sk_shift(A)
#define sk_SSL_CIPHER_dup(A) sk_dup(A)
#define sk_SSL_CIPHER_unshift(A, B) sk_unshift(A, (char *) B)
#define sk_SSL_CIPHER_pop(A) sk_pop(A)
#define sk_SSL_CIPHER_delete_ptr(A, B) sk_delete_ptr(A, B)

#define sk_X509_EXTENSION_num sk_num
#define sk_X509_EXTENSION_value (X509_EXTENSION *)sk_value
#define sk_X509_EXTENSION_push(A, B) sk_push(A, (char *) B)
#define sk_X509_EXTENSION_new_null sk_new_null
#define sk_X509_EXTENSION_pop_free sk_pop_free

#define sk_X509_REVOKED_num sk_num
#define sk_X509_REVOKED_value (X509_REVOKED*)sk_value

#endif

#include "openssl/ssl.h"
#include "openssl/err.h"
#include "openssl/bio.h"
#include "openssl/pem.h"
#include "openssl/x509.h"
#include "openssl/stack.h"

/**********************************************************************
                               Define constants
**********************************************************************/

#define X509_CERT_DIR "X509_CERT_DIR"
#define X509_CERT_FILE  "X509_CERT_FILE"
#define X509_USER_PROXY "X509_USER_PROXY"
#define X509_USER_CERT  "X509_USER_CERT"
#define X509_USER_KEY   "X509_USER_KEY"
#define X509_USER_DELEG_PROXY   "X509_USER_DELEG_PROXY"
#define X509_USER_DELEG_FILE    "x509up_p"
#define X509_USER_PROXY_FILE    "x509up_u"

/* This is added after the CA name hash to make the policy filename */
#define SIGNING_POLICY_FILE_EXTENSION   ".signing_policy"

#ifdef WIN32
#define GSI_REGISTRY_DIR "software\\Globus\\GSI"
#define X509_DEFAULT_CERT_DIR   ".globus\\certificates"
#define X509_DEFAULT_USER_CERT  ".globus\\usercert.pem"
#define X509_DEFAULT_USER_CERT_P12  ".globus\\usercert.p12"
#define X509_DEFAULT_USER_CERT_P12_GT  ".globus\\usercred.p12"
#define X509_DEFAULT_USER_KEY   ".globus\\userkey.pem"
#define X509_INSTALLED_CERT_DIR "share\\certificates"
#define X509_INSTALLED_HOST_CERT_DIR "NEEDS_TO_BE_DETERMINED"
#define X509_DEFAULT_HOST_CERT  "NEEDS_TO_BE_DETERMINED"
#define X509_DEFAULT_HOST_KEY   "NEEDS_TO_BE_DETERMINED"
#else
#define X509_DEFAULT_CERT_DIR   ".globus/certificates"
#define X509_DEFAULT_USER_CERT  ".globus/usercert.pem"
#define X509_DEFAULT_USER_CERT_P12  ".globus/usercert.p12"
#define X509_DEFAULT_USER_CERT_P12_GT  ".globus/usercred.p12"
#define X509_DEFAULT_USER_KEY   ".globus/userkey.pem"
#define X509_INSTALLED_CERT_DIR "share/certificates"
#define X509_INSTALLED_HOST_CERT_DIR "/etc/grid-security/certificates"
#define X509_DEFAULT_HOST_CERT  "/etc/grid-security/hostcert.pem"
#define X509_DEFAULT_HOST_KEY   "/etc/grid-security/hostkey.pem"
#endif

/*
 * To allow the use of the proxy_verify_callback with 
 * applications which already use the SSL_set_app_data,
 * we define here the index for use with the 
 * SSL_set_ex_data. This is hardcoded today, but
 * if needed we could add ours at the highest available,
 * then look at all of them for the magic number. 
 * To allow for recursive calls to proxy_verify_callback
 * when verifing a delegate cert_chain, we also have 
 * PVD_STORE_EX_DATA_IDX
 */

#define PVD_SSL_EX_DATA_IDX     5
#define PVD_STORE_EX_DATA_IDX   6


#define PVD_MAGIC_NUMBER        22222
#define PVXD_MAGIC_NUMBER       33333

/* Used by ERR_set_continue_needed as a flag for error routines */
#define ERR_DISPLAY_CONTINUE_NEEDED     64

/* Location relative to ERR_LIB_USER where PRXYERR library will be stored */
#define ERR_USER_LIB_PRXYERR_NUMBER     ERR_LIB_USER

/*
 * Use the SSLeay error facility with the ERR_LIB_USER
 */

#define PRXYerr(f,r) ERR_PUT_error(ERR_USER_LIB_PRXYERR_NUMBER,(f),(r),__FILE__,__LINE__)

/* 
 * SSLeay 0.9.0 added the error_data feature. We may be running
 * with 0.8.1 which does not have it, if so, define a dummy
 * ERR_add_error_data and ERR_get_error_line_data
        
*/

#if SSLEAY_VERSION_NUMBER < 0x0900
void ERR_add_error_data( VAR_PLIST( int, num ) );

unsigned long ERR_get_error_line_data(char **file,int *line,
                                      char **data, int *flags);
#endif

void
ERR_set_continue_needed(void);

/*
 * defines for function codes our minor error codes
 * These match strings defined in gsserr.c.
 */

#define PRXYERR_F_BASE                          100
       
#define PRXYERR_F_PROXY_GENREQ                 PRXYERR_F_BASE + 0
#define PRXYERR_F_PROXY_SIGN                   PRXYERR_F_BASE + 1
#define PRXYERR_F_VERIFY_CB                    PRXYERR_F_BASE + 2
#define PRXYERR_F_PROXY_LOAD                   PRXYERR_F_BASE + 3
#define PRXYERR_F_PROXY_TMP                    PRXYERR_F_BASE + 4
#define PRXYERR_F_INIT_CRED                    PRXYERR_F_BASE + 5
#define PRXYERR_F_LOCAL_CREATE                 PRXYERR_F_BASE + 6
#define PRXYERR_F_CB_NO_PW                     PRXYERR_F_BASE + 7
#define PRXYERR_F_GET_CA_SIGN_PATH             PRXYERR_F_BASE + 8
#define PRXYERR_F_PROXY_SIGN_EXT               PRXYERR_F_BASE + 9
#define PRXYERR_F_PROXY_VERIFY_NAME            PRXYERR_F_BASE + 10
#define PRXYERR_F_PROXY_CONSTRUCT_NAME         PRXYERR_F_BASE + 11
#define PRXYERR_F_VOMS_GET_CERT_TYPE           PRXYERR_F_BASE + 12

/* 
 * defines for reasons 
 * The match strings defined in gsserr.c
 * These are also used for the minor_status codes.
 * We want to make sure these don't overlap with the errors in
 * gssapi_ssleay.h.
 */

#define PRXYERR_R_BASE                          1000

#define PRXYERR_R_PROCESS_PROXY_KEY            PRXYERR_R_BASE + 1
#define PRXYERR_R_PROCESS_REQ                  PRXYERR_R_BASE + 2
#define PRXYERR_R_PROCESS_SIGN                 PRXYERR_R_BASE + 3
#define PRXYERR_R_MALFORM_REQ                  PRXYERR_R_BASE + 4
#define PRXYERR_R_SIG_VERIFY                   PRXYERR_R_BASE + 5
#define PRXYERR_R_SIG_BAD                      PRXYERR_R_BASE + 6
#define PRXYERR_R_PROCESS_PROXY                PRXYERR_R_BASE + 7
#define PRXYERR_R_PROXY_NAME_BAD               PRXYERR_R_BASE + 8
#define PRXYERR_R_PROCESS_SIGNC                PRXYERR_R_BASE + 9
#define PRXYERR_R_BAD_PROXY_ISSUER             PRXYERR_R_BASE + 10
#define PRXYERR_R_PROBLEM_PROXY_FILE           PRXYERR_R_BASE + 11
#define PRXYERR_R_SIGN_NOT_CA                  PRXYERR_R_BASE + 12
#define PRXYERR_R_PROCESS_KEY                  PRXYERR_R_BASE + 13
#define PRXYERR_R_PROCESS_CERT                 PRXYERR_R_BASE + 14
#define PRXYERR_R_PROCESS_CERTS                PRXYERR_R_BASE + 15
#define PRXYERR_R_NO_TRUSTED_CERTS             PRXYERR_R_BASE + 16
#define PRXYERR_R_PROBLEM_KEY_FILE             PRXYERR_R_BASE + 17
#define PRXYERR_R_USER_ZERO_LENGTH_KEY_FILE    PRXYERR_R_BASE + 18
#define PRXYERR_R_SERVER_ZERO_LENGTH_KEY_FILE  PRXYERR_R_BASE + 19
#define PRXYERR_R_ZERO_LENGTH_CERT_FILE        PRXYERR_R_BASE + 20
#define PRXYERR_R_PROBLEM_USER_NOCERT_FILE     PRXYERR_R_BASE + 21
#define PRXYERR_R_PROBLEM_SERVER_NOCERT_FILE   PRXYERR_R_BASE + 22
#define PRXYERR_R_PROBLEM_USER_NOKEY_FILE      PRXYERR_R_BASE + 23
#define PRXYERR_R_PROBLEM_SERVER_NOKEY_FILE    PRXYERR_R_BASE + 24
#define PRXYERR_R_USER_CERT_EXPIRED            PRXYERR_R_BASE + 25
#define PRXYERR_R_SERVER_CERT_EXPIRED          PRXYERR_R_BASE + 26
#define PRXYERR_R_CRL_SIGNATURE_FAILURE        PRXYERR_R_BASE + 27
#define PRXYERR_R_CRL_NEXT_UPDATE_FIELD        PRXYERR_R_BASE + 28
#define PRXYERR_R_CRL_HAS_EXPIRED              PRXYERR_R_BASE + 29
#define PRXYERR_R_CERT_REVOKED                 PRXYERR_R_BASE + 30
#define PRXYERR_R_NO_HOME                      PRXYERR_R_BASE + 31
#define PRXYERR_R_LPROXY_MISSED_USED           PRXYERR_R_BASE + 32
#define PRXYERR_R_LPROXY_REJECTED              PRXYERR_R_BASE + 33
#define PRXYERR_R_KEY_CERT_MISMATCH            PRXYERR_R_BASE + 34
#define PRXYERR_R_WRONG_PASSPHRASE             PRXYERR_R_BASE + 35
#define PRXYERR_R_CA_POLICY_VIOLATION          PRXYERR_R_BASE + 36
#define PRXYERR_R_CA_POLICY_RETRIEVE           PRXYERR_R_BASE + 37
#define PRXYERR_R_CA_POLICY_PARSE              PRXYERR_R_BASE + 38
#define PRXYERR_R_PROBLEM_CLIENT_CA            PRXYERR_R_BASE + 39
#define PRXYERR_R_CB_NO_PW                     PRXYERR_R_BASE + 40
#define PRXYERR_R_CB_CALLED_WITH_ERROR         PRXYERR_R_BASE + 41
#define PRXYERR_R_CB_ERROR_MSG                 PRXYERR_R_BASE + 42
#define PRXYERR_R_CLASS_ADD_OID                PRXYERR_R_BASE + 43
#define PRXYERR_R_CLASS_ADD_EXT                PRXYERR_R_BASE + 44
#define PRXYERR_R_DELEGATE_VERIFY              PRXYERR_R_BASE + 45
#define PRXYERR_R_EXT_ADD                      PRXYERR_R_BASE + 46
#define PRXYERR_R_DELEGATE_COPY                PRXYERR_R_BASE + 47
#define PRXYERR_R_DELEGATE_CREATE              PRXYERR_R_BASE + 48
#define PRXYERR_R_BUFFER_TOO_SMALL             PRXYERR_R_BASE + 49
#define PRXYERR_R_PROXY_EXPIRED                PRXYERR_R_BASE + 50
#define PRXYERR_R_NO_PROXY                     PRXYERR_R_BASE + 51
#define PRXYERR_R_CA_UNKNOWN                   PRXYERR_R_BASE + 52
#define PRXYERR_R_CA_NOPATH                    PRXYERR_R_BASE + 53
#define PRXYERR_R_CA_NOFILE                    PRXYERR_R_BASE + 54
#define PRXYERR_R_CA_POLICY_ERR                PRXYERR_R_BASE + 55
#define PRXYERR_R_INVALID_CERT                 PRXYERR_R_BASE + 56
#define PRXYERR_R_CERT_NOT_YET_VALID           PRXYERR_R_BASE + 57
#define PRXYERR_R_LOCAL_CA_UNKNOWN             PRXYERR_R_BASE + 58
#define PRXYERR_R_REMOTE_CRED_EXPIRED          PRXYERR_R_BASE + 59
#define PRXYERR_R_OUT_OF_MEMORY                PRXYERR_R_BASE + 60
#define PRXYERR_R_BAD_ARGUMENT                 PRXYERR_R_BASE + 61
#define PRXYERR_R_BAD_MAGIC                    PRXYERR_R_BASE + 62
#define PRXYERR_R_UNKNOWN_CRIT_EXT             PRXYERR_R_BASE + 63

#define PRXYERR_R_NON_COMPLIANT_PROXY                   PRXYERR_R_BASE + 64
#define PRXYERR_R_ERROR_GETTING_NAME_ENTRY_OF_SUBJECT   PRXYERR_R_BASE + 65
#define PRXYERR_R_ERROR_COPYING_SUBJECT                 PRXYERR_R_BASE + 66
#define PRXYERR_R_ERROR_GETTING_CN_ENTRY                PRXYERR_R_BASE + 67
#define PRXYERR_R_ERROR_BUILDING_SUBJECT                 PRXYERR_R_BASE + 68



/* NOTE: Don't go over 1500 here or will conflict with errors in scutils.h */


/**********************************************************************
                               Type definitions
**********************************************************************/

/* proxy_verify_ctx_desc - common to all verifys */

typedef struct proxy_verify_ctx_desc_struct {
    int                                 magicnum ;  
    char *                              certdir; 
    time_t                              goodtill;
} proxy_verify_ctx_desc ;

/* proxy_verify_desc - allows for recursive verifys with delegation */

typedef struct proxy_verify_desc_struct proxy_verify_desc;

struct proxy_verify_desc_struct {
    int                                 magicnum;
    proxy_verify_desc *                 previous;
    proxy_verify_ctx_desc *             pvxd;
    int                                 flags;
    X509_STORE_CTX *                    cert_store;
    int                                 recursive_depth;
    int                                 proxy_depth;
    int                                 cert_depth;
    int                                 limited_proxy;
    STACK_OF(X509) *                    cert_chain; /*  X509 */
    int                                 multiple_limited_proxy_ok;
};

/**********************************************************************
                               Global variables
**********************************************************************/

/**********************************************************************
                               Function prototypes
**********************************************************************/

int
ERR_load_prxyerr_strings(int i);

int
ERR_load_proxy_error_strings();

int proxy_load_user_cert_and_key_pkcs12(const char *user_cert,
                                        X509 **cert,
                                        STACK_OF(X509) **stack,
                                        EVP_PKEY **pkey,
                                        int (*pw_cb) ());

int
proxy_get_filenames(
    int                                 proxy_in,
    char **                             p_cert_file,
    char **                             p_cert_dir,
    char **                             p_user_proxy,
    char **                             p_user_cert,
    char **                             p_user_key);

int
proxy_load_user_cert(
    const char *                        user_cert,
    X509 **                             certificate,
    int                                 (*pw_cb)(),
    unsigned long *                     hSession);

int
proxy_load_user_key(
    EVP_PKEY **                         private_key,
    X509 * ucert,
    const char *                        user_key,
    int                                 (*pw_cb)(),
    unsigned long *                     hSession);

void
proxy_verify_init(
    proxy_verify_desc *                 pvd,
    proxy_verify_ctx_desc *             pvxd);

void
proxy_verify_release(
    proxy_verify_desc *                 pvd);

void
proxy_verify_ctx_init(
                      proxy_verify_ctx_desc *pvxd);
void
proxy_verify_ctx_release(
                      proxy_verify_ctx_desc *pvxd);

int
proxy_check_proxy_name(
    X509 *);

int 
proxy_check_issued(
    X509_STORE_CTX *                    ctx,
    X509 *                              x,
    X509 *                              issuer);

int
proxy_verify_certchain(
    STACK_OF(X509) *                    certchain,
    proxy_verify_desc *                 ppvd);

int
proxy_verify_callback(
    int                                 ok,
    X509_STORE_CTX *                    ctx);

int
proxy_genreq(
    X509 *                              ucert,
    X509_REQ **                         reqp,
    EVP_PKEY **                         pkeyp,
    int                                 bits,
    const char *                        newdn,
    int                                 (*callback)());

int
proxy_sign(
    X509 *                              user_cert,
    EVP_PKEY *                          user_private_key,
    X509_REQ *                          req,
    X509 **                             new_cert,
    int                                 seconds,
    STACK_OF(X509_EXTENSION) *          extensions,
    int                                 limited_proxy,
    int                                 proxyver,
    const char *                        newdn,
    const char *                        newissuer,
    int                                 pastproxy,
    const char *                        newserial,
    int                                 selfsigned
);

int
proxy_sign_ext(
    X509 *                              user_cert,
    EVP_PKEY *                          user_private_key,
    const EVP_MD *                      method,
    X509_REQ *                          req,
    X509 **                             new_cert,
    X509_NAME *                         subject_name,
    X509_NAME *                         issuer_name,    
    int                                 seconds,
    STACK_OF(X509_EXTENSION) *          extensions,
    int                                 proxyver,
    int                                 pastproxy,
    const char *                        newserial,
    int                                 selfsigned);

int
proxy_check_subject_name(
    X509_REQ *                          req,
    X509_NAME *                         subject_name);

int
proxy_construct_name(
    X509 *                              cert,
    X509_NAME **                        name,
    char *                              newcn,
    unsigned int                        len);

int
proxy_marshal_tmp(
    X509 *                              ncert,
    EVP_PKEY *                          npkey,
    X509 *                              ucert,
    STACK_OF(X509) *                    store_ctx,
    char **                             filename);

int
proxy_marshal_bp(
    BIO *                               bp,
    X509 *                              ncert,
    EVP_PKEY *                          npkey,
    X509 *                              ucert,
    STACK_OF(X509) *                    store_ctx);

int
proxy_load_user_proxy(
    STACK_OF(X509) *                    cert_chain,
    const char *                        file);

int
proxy_get_base_name(
    X509_NAME *                         subject);

X509_EXTENSION *
proxy_extension_class_add_create(
    void *                              buffer, 
    size_t                              length);
/*
 * SSLeay does not have a compare time function
 * So we add a convert to time_t function
 */

time_t
ASN1_UTCTIME_mktime(
    ASN1_UTCTIME *                     ctm);

time_t ASN1_TIME_mktime(ASN1_TIME *ctm);

int PRIVATE determine_filenames(char **cacert, char **certdir, char **outfile,
                                char **certfile, char **keyfile, int noregen);
int load_credentials(const char *certname, const char *keyname,
                             X509 **cert, STACK_OF(X509) **stack, EVP_PKEY **key,
                             int (*callback)());
int PRIVATE load_certificate_from_file(FILE *file, X509 **cert, 
                                       STACK_OF(X509) **stack);

int
proxy_app_verify_callback(X509_STORE_CTX *ctx, UNUSED(void *empty));

STACK_OF(X509) *load_chain(BIO *in, char*);

int my_txt2nid(char *name);

EXTERN_C_END

#endif /* _SSLUTILS_H */
