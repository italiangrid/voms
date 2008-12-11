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

#include "replace.h"

#include <sys/types.h>
#include <string.h>
#include <stdlib.h>
#include "gssapi_compat.h"

#include <openssl/asn1.h>
#include <openssl/x509.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/bio.h>

#include "credentials.h"
#include "sslutils.h"

int
globus(int version)
{
  if (version == 0) {
    char *gver = getenv("GLOBUS_VERSION");

    if (gver) {
      char *tmp;
      
      version = strtol(gver, &tmp, 10);
      if (!(*tmp))
        return 22;
    }
  }
  
  if (version >= 22 || version == 0)
    version = 22;

  return version;
}


X509 *
decouple_cred(gss_cred_id_t credential, STACK_OF(X509) **stk)
{
  if (!stk || (credential == 0L))
    return NULL;

  *stk = ((gss2_cred_id_desc *)credential)->cred_handle->cert_chain;
  return ((gss2_cred_id_desc *)credential)->cred_handle->cert;
}

X509 *
get_real_cert(X509 *base, STACK_OF(X509) *stk)
{
  X509 *cert = NULL;
  int i;

  if (!proxy_check_proxy_name(base))
    return base;

  /* Determine id data */
  for (i = 0; i < sk_X509_num(stk); i++) {
    cert = sk_X509_value(stk, i);
    if (!proxy_check_proxy_name(cert)) {
      return cert;
    }
  }
  return NULL;
}

int 
get_issuer(X509 *cert, char **buffer)
{
  X509_NAME *name;
  char *result;
  int gotit = 0;

  name = X509_get_issuer_name(cert);
  result = X509_NAME_oneline(name, NULL, 0);

  free(*buffer);
  *buffer = (char *)malloc(strlen(result)+1);
  if (*buffer) {
    strncpy(*buffer, result, strlen(result)+1);
    gotit = 1;
  }
  OPENSSL_free(result);
  return gotit;
}

X509 *
load_cert(FILE *file, STACK_OF(X509) **stack, EVP_PKEY **key)
{
  STACK_OF(X509) *certstack = NULL;
  STACK_OF(X509_INFO) *sk = NULL;
  BIO *in = NULL;
  int first = 1;
  X509 *x = NULL;

  in = BIO_new_fp(file, BIO_NOCLOSE);

  if (stack) {
    if (!(*stack))
      certstack = *stack = sk_X509_new_null();
    else
      certstack = *stack;
  }

  if (in) {
    if ((sk = PEM_X509_INFO_read_bio(in, NULL, NULL, NULL))) {

      while (sk_X509_INFO_num(sk)) {

        X509_INFO *xi = sk_X509_INFO_shift(sk);
        
        if (xi->x509 != NULL) {
          if (first) {
            x = xi->x509;
            xi->x509 = NULL;
            first = 0;
          }
          else if (certstack) {
            sk_X509_push(certstack, xi->x509);
            xi->x509 = NULL;
          }
        }

        if (xi->x_pkey && key) {
          (*key) = xi->x_pkey->dec_pkey;
          xi->x_pkey = NULL;
        }
        X509_INFO_free(xi);
      }
    }
  }
  
  BIO_free(in);

  if (sk)
    sk_X509_INFO_pop_free(sk, X509_INFO_free);

  return x;
}

X509 *
load_cert_name(const char *filename, STACK_OF(X509) **stack, EVP_PKEY **key)
{
  FILE *f = NULL;

  if (!filename)
    return NULL;

  f = fopen(filename, "rb");

  if (f) {
    X509 *ret = load_cert(f, stack, key);
    fclose(f);
    return ret;
  }
  return NULL;
}
  
static int /* MS_CALLBACK */
cb(int ok, X509_STORE_CTX *ctx)
{
  char buf[256];

  if (!ok) {
    X509_NAME_oneline(X509_get_subject_name(ctx->current_cert),buf,256);
    if (ctx->error == X509_V_ERR_CERT_HAS_EXPIRED) ok=1;
    /* since we are just checking the certificates, it is
     * ok if they are self signed. But we should still warn
     * the user.
     */
    if (ctx->error == X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT) ok=1;
    /* Continue after extension errors too */
    if (ctx->error == X509_V_ERR_INVALID_CA) ok=1;
    if (ctx->error == X509_V_ERR_PATH_LENGTH_EXCEEDED) ok=1;
    if (ctx->error == X509_V_ERR_INVALID_PURPOSE) ok=1;
    if (ctx->error == X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT) ok=1;
  }
  return(ok);
}

int
verify_credentials(X509 *cert, STACK_OF(X509) *stack)
{
  X509_STORE *ctx = NULL;
  X509_STORE_CTX *csc = NULL;
  X509_LOOKUP *lookup = NULL;
  int index = 0;
  char *ca_dir;

  csc = X509_STORE_CTX_new();
  ctx = X509_STORE_new();

  /* Determine CA DIR */
  ca_dir = getenv("X509_CERT_DIR");
  if (!ca_dir || !strlen(ca_dir))
    ca_dir = "/etc/grid-security/certificates";

  if (ctx && csc) {
    X509_STORE_set_verify_cb_func(ctx,cb);
#ifdef SIGPIPE
    signal(SIGPIPE,SIG_IGN);
#endif
    CRYPTO_malloc_init();
    if ((lookup = X509_STORE_add_lookup(ctx, X509_LOOKUP_file()))) {
      X509_LOOKUP_load_file(lookup, NULL, X509_FILETYPE_DEFAULT);
      if ((lookup=X509_STORE_add_lookup(ctx,X509_LOOKUP_hash_dir()))) {
        X509_LOOKUP_add_dir(lookup, ca_dir, X509_FILETYPE_PEM);
        ERR_clear_error();

        X509_STORE_CTX_init(csc, ctx, cert, stack);
        csc->check_issued = proxy_check_issued;
        index = X509_verify_cert(csc);
      }
    }
  }
  if (ctx) X509_STORE_free(ctx);
  if (csc) X509_STORE_CTX_free(csc);

  return (index != 0);

}

EVP_PKEY *
get_private_key(void *credential)
{
  globus_gsi_cred_handle_t ggch;
  EVP_PKEY *pkey = NULL;

  if (!credential)
    return NULL;

  ggch = ((gss2_cred_id_desc *)credential)->cred_handle;
  if (ggch)
    pkey = ggch->key;
  else
    return NULL;

  return pkey;
}

int get_own_data(gss_cred_id_t credential, EVP_PKEY **key, char **issuer, X509 **pcert)
{
  /*  EVP_PKEY *pkey = NULL; */
  STACK_OF(X509) *stk = NULL;
  X509 *cert = NULL;

  if (!credential || !key || !issuer || !pcert)
    return 0;

  cert = decouple_cred(credential, &stk);
  *key   = get_private_key(credential);

  *pcert = get_real_cert(cert, stk);

  if (*pcert && *key) {
    return get_issuer(*pcert, issuer);
  }
  else
    return 0;
}


char *
get_peer_serial(X509 *cert)
{
  char *res = NULL;
  ASN1_INTEGER * tmp;

  if (!cert)
    return NULL;

  tmp = X509_get_serialNumber(cert);
  if (tmp) 
  {
    BIGNUM *bn = ASN1_INTEGER_to_BN(tmp, NULL);
    if (bn)
      res = BN_bn2hex(bn);
    BN_free(bn);
  }
  
  return res;
}
 
