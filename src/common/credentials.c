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
#include "globus_config.h"
#include "gssapi_compat.h"
#include "gssapi.h"
#include "globus_gss_assist.h"

#include <openssl/asn1.h>
#include <openssl/x509.h>
#include <openssl/evp.h>
#include <openssl/bn.h>

#include "credentials.h"


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
get_own_cert(void)
{
  OM_uint32                   major_status = 0;
  OM_uint32                   minor_status = 0;
  gss_cred_id_t credential = GSS_C_NO_CREDENTIAL;
  X509 *cert, *base;
  X509 *ret = NULL;
  STACK_OF(X509) *stk;

  /* acquire our credentials */
  major_status = globus_gss_assist_acquire_cred(&minor_status,
						GSS_C_INITIATE,
						&credential);

  if(major_status != GSS_S_COMPLETE) {
    gss_release_cred(&minor_status, &credential);
    return NULL;
  }


  if ((base = decouple_cred(credential, 0, &stk))) {
    cert = get_real_cert(base, stk);
    if (cert) {
      ret = (X509 *)ASN1_dup((int (*)())i2d_X509, (char * (*)())d2i_X509, (char *)cert);
    }
  }
  gss_release_cred(&minor_status, &credential);
  return ret;
}

X509 *
decouple_cred(gss_cred_id_t credential, int version, STACK_OF(X509) **stk)
{
  if (!stk || (credential == GSS_C_NO_CREDENTIAL))
    return NULL;

  if (version == 0)
    version = globus(0);

  if (version == 20) {
    *stk = ((gss_cred_id_desc *)credential)->pcd->cert_chain;
    return ((gss_cred_id_desc *)credential)->pcd->ucert;
  }
  else if (version == 22) {
    *stk = ((gss2_cred_id_desc *)credential)->cred_handle->cert_chain;
    return ((gss2_cred_id_desc *)credential)->cred_handle->cert;
  }
  else
    return NULL;
}

X509 *
decouple_ctx(gss_ctx_id_t context, int version, STACK_OF(X509) **stk)
{
  if (!stk || (context == GSS_C_NO_CONTEXT))
    return NULL;

  if (version == 0)
    version = globus(0);

  if (version == 22) {
    *stk = ((gss2_ctx_id_desc *)context)->peer_cred_handle->cred_handle->cert_chain;
    return ((gss2_ctx_id_desc *)context)->peer_cred_handle->cred_handle->cert;
  }
  else if (version == 20) {
    *stk = ((gss_ctx_id_desc *)context)->cred_handle->pcd->cert_chain;
    return ((gss_ctx_id_desc *)context)->cred_handle->pcd->ucert;
  }
  else
    return NULL;
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

EVP_PKEY *
get_delegated_public_key(gss_ctx_id_t context, int globusver)
{
  EVP_PKEY *pkey = NULL;

  if (!context)
    return NULL;

  if (globusver == 0)
    globusver = globus(0);

  if (globusver == 20)
    pkey = X509_extract_key(((((gss_ctx_id_desc *)context)->gs_ssl)->session)->peer);
  else if (globusver == 22)
    pkey = X509_extract_key(((((gss2_ctx_id_desc *)context)->gss_ssl)->session)->peer);

  return pkey;
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


EVP_PKEY *
get_private_key(void *credential, int globusver)
{
  proxy_cred_desc *pcd;
  globus_gsi_cred_handle_t ggch;
  EVP_PKEY *pkey = NULL;

  if (!credential)
    return NULL;

  if (globusver == 20) {
    pcd = ((gss_cred_id_desc *)credential)->pcd;
    if (pcd)
      pkey = pcd->upkey;
  }
  else if (globusver == 22) {
    ggch = ((gss2_cred_id_desc *)credential)->cred_handle;
    if (ggch)
      pkey = ggch->key;
  }
  else
    return NULL;

  return pkey;
}

int get_own_data(gss_cred_id_t credential, int globusver, EVP_PKEY **key, char **issuer, X509 **pcert)
{
  /*  EVP_PKEY *pkey = NULL; */
  STACK_OF(X509) *stk = NULL;
  X509 *cert = NULL;

  if (!credential || !key || !issuer || !pcert)
    return 0;

  cert = decouple_cred(credential, globusver, &stk);
  *key   = get_private_key(credential, globusver);

  *pcert = get_real_cert(cert, stk);

  if (*pcert && *key) {
    return get_issuer(*pcert, issuer);
  }
  else
    return 0;
}

int get_peer_data(gss_ctx_id_t context, int globusver, EVP_PKEY **key, char **issuer, X509 **pcert)
{
  STACK_OF(X509) *stk = NULL;
  X509 *cert = NULL;

  if (!context || !key || !issuer || !pcert)
    return 0;

  cert = decouple_ctx(context, globusver, &stk);
  *pcert = get_real_cert(cert, stk);
  *key = X509_extract_key(*pcert);

  if (*key && *pcert)
    return get_issuer(*pcert, issuer);
  else
    return 0;
}

char *
get_globusid(gss_cred_id_t handle)
{
  char *globusid;
  char *globusid_tmp;
  gss_name_t server_name = GSS_C_NO_NAME;
  gss_buffer_desc server_buffer_desc = GSS_C_EMPTY_BUFFER;
  gss_buffer_t server_buffer = &server_buffer_desc;
  OM_uint32 major_status = 0;
  OM_uint32 minor_status = 0;
  OM_uint32 minor_status2 = 0;

  if ((major_status = gss_inquire_cred(&minor_status,
				       handle,
				       &server_name,
				       NULL, NULL, NULL)) == GSS_S_COMPLETE) {
    major_status = gss_display_name(&minor_status,
				    server_name, server_buffer, NULL);
    gss_release_name(&minor_status2, &server_name);
  }
  /*
   * The gssapi_cleartext does not implement gss_inquire_cred,
   * so fall back to using environment variable.
   */
  if (major_status == GSS_S_COMPLETE) {
    globusid = (char *)server_buffer_desc.value;
  }
  else {
    return NULL;
  }
  globusid_tmp = strdup(globusid);

  if (server_buffer_desc.value) {
    gss_release_buffer(&minor_status2, server_buffer);
  }
  return globusid_tmp;
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
 
