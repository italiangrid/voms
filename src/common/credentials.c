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
  
  if (version >= 42 || version == 0)
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
 
