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
#include "config.h"

#include <openssl/asn1.h>
#include <openssl/asn1_mac.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/bn.h>
#include <string.h>

#include "newformat.h"
#include "acerrors.h"

#define ERROR(e) do { err = (e); goto err; } while (0)

int writeac(X509 *issuerc, STACK_OF(X509) *issuerstack, 
            X509 *holder, EVP_PKEY *pkey, 
	    BIGNUM *s, char **c, char *t, AC **ac, const char *vo, 
	    const char *uri, int valid, int old)
{
  AC *a;
  X509_NAME *name1, *name2, *subjdup, *issdup;
  GENERAL_NAME *dirn, *dirn2;
  ASN1_INTEGER  *serial, *holdserial, *version;
  ASN1_BIT_STRING *uid;
  AC_ATTR *capabilities;
  AC_IETFATTR *capnames;
  ASN1_OBJECT *cobj;
  X509_ALGOR *alg1, *alg2;
  ASN1_GENERALIZEDTIME *time1, *time2;
  X509_EXTENSION *norevavail, *targets, *auth, *certstack;
  ASN1_NULL *null;
  int i = 0;
  int err = AC_ERR_UNKNOWN;

  time_t curtime;

  a = NULL;
  name1 = name2 = subjdup = issdup = NULL;
  dirn = dirn2 = NULL;
  version = serial = holdserial = NULL;
  time1 = time2 = NULL;
  uid = NULL;
  capabilities = NULL;
  capnames = NULL;
  cobj = NULL;
  certstack = auth = targets = norevavail = NULL;

  if (!issuerc || !holder || !s || !c || !ac || !pkey)
    return AC_ERR_PARAMETERS;

  a = *ac;

  name1 = X509_get_subject_name(issuerc);

  if (old)
    name2 = X509_get_subject_name(holder);
  else
    name2 = X509_get_issuer_name(holder);

  if (!name1)
    ERROR(X509_ERR_ISSUER_NAME);

  if (!name2)
    ERROR(X509_ERR_HOLDER_NAME);


  time(&curtime);
  time1 = ASN1_GENERALIZEDTIME_set(NULL, curtime);
  time2 = ASN1_GENERALIZEDTIME_set(NULL, curtime+valid);

  subjdup             = X509_NAME_dup(name2);
  issdup              = X509_NAME_dup(name1);
  dirn                = GENERAL_NAME_new();
  dirn2               = GENERAL_NAME_new();
  holdserial          = M_ASN1_INTEGER_dup(holder->cert_info->serialNumber);
  serial              = BN_to_ASN1_INTEGER(s, NULL);
  version             = BN_to_ASN1_INTEGER((BIGNUM *)(BN_value_one()), NULL);
  capabilities        = AC_ATTR_new();
  cobj                = OBJ_txt2obj("idatcap",0);
  capnames            = AC_IETFATTR_new();
  null                = ASN1_NULL_new();

  if (!subjdup || !issdup || !dirn || !dirn2 || !holdserial || !serial ||
      !capabilities || !cobj || !capnames || !time1 || !time2 ||
      !null)
    ERROR(AC_ERR_MEMORY);

  while(c[i]) {
    ASN1_OCTET_STRING *tmpc = ASN1_OCTET_STRING_new();

    if (!tmpc) {
      ASN1_OCTET_STRING_free(tmpc);
      ERROR(AC_ERR_MEMORY);
    }
    ASN1_OCTET_STRING_set(tmpc, c[i], strlen(c[i]));
    sk_AC_IETFATTRVAL_push(capnames->values, (AC_IETFATTRVAL *)tmpc);
    i++;
  }
  {
    GENERAL_NAME *g = GENERAL_NAME_new();
    ASN1_IA5STRING *tmpr = ASN1_IA5STRING_new();
    char *buffer=(char *)malloc(strlen(vo)+strlen(uri)+4);

    if (!tmpr || !g || !buffer) {
      GENERAL_NAME_free(g);
      ASN1_IA5STRING_free(tmpr);
      free(buffer);
      ERROR(AC_ERR_MEMORY);
    }
    strcpy(buffer, vo);
    strcat(buffer, "://");
    strcat(buffer,uri);
    ASN1_STRING_set(tmpr, buffer, strlen(buffer));
    free(buffer);
    g->type  = GEN_URI;
    g->d.ia5 = tmpr;
    sk_GENERAL_NAME_push(capnames->names, g);
  }


  sk_AC_IETFATTR_push(capabilities->ietfattr, capnames);
  ASN1_OBJECT_free(capabilities->type);
  capabilities->type = cobj;

  sk_AC_ATTR_push(a->acinfo->attrib, capabilities);


  STACK_OF(X509) *stk = NULL;
  if (issuerstack)
    stk = sk_X509_dup(issuerstack);
  else
    stk = sk_X509_new_null();
  sk_X509_push(stk, X509_dup(issuerc));
  certstack = X509V3_EXT_conf_nid(NULL, NULL, OBJ_txt2nid("certseq"), (char*)stk);
  sk_X509_free(stk);

  /* Create extensions */
  norevavail=X509V3_EXT_conf_nid(NULL, NULL, OBJ_txt2nid("idcenoRevAvail"), "loc");
  if (!norevavail)
    ERROR(AC_ERR_NO_EXTENSION);
/*   X509_EXTENSION_set_critical(norevavail, 0); */

  auth=X509V3_EXT_conf_nid(NULL, NULL, OBJ_txt2nid("authKeyId"), (char *)issuerc);
  if (!auth)
    ERROR(AC_ERR_NO_EXTENSION);

  if (t) {
    targets=X509V3_EXT_conf_nid(NULL, NULL, OBJ_txt2nid("idceTargets"), t);
    if (!targets)
      ERROR(AC_ERR_NO_EXTENSION);

    X509_EXTENSION_set_critical(targets,1);
    sk_X509_EXTENSION_push(a->acinfo->exts, targets);
  }

  sk_X509_EXTENSION_push(a->acinfo->exts, norevavail);
  sk_X509_EXTENSION_push(a->acinfo->exts, auth);
  if (certstack)
    sk_X509_EXTENSION_push(a->acinfo->exts, certstack);

  alg1 = X509_ALGOR_dup(issuerc->cert_info->signature);
  alg2 = X509_ALGOR_dup(issuerc->sig_alg);

  if (issuerc->cert_info->issuerUID)
    if (!(uid = M_ASN1_BIT_STRING_dup(issuerc->cert_info->issuerUID)))
      ERROR(AC_ERR_MEMORY);

  ASN1_INTEGER_free(a->acinfo->holder->baseid->serial);
  ASN1_INTEGER_free(a->acinfo->serial);
  ASN1_INTEGER_free(a->acinfo->version);
  ASN1_GENERALIZEDTIME_free(a->acinfo->validity->notBefore);
  ASN1_GENERALIZEDTIME_free(a->acinfo->validity->notAfter);
  dirn->d.dirn = subjdup;
  dirn->type = GEN_DIRNAME;
  sk_GENERAL_NAME_push(a->acinfo->holder->baseid->issuer, dirn);
  dirn2->d.dirn = issdup;
  dirn2->type = GEN_DIRNAME;
  sk_GENERAL_NAME_push(a->acinfo->form->names, dirn2);
  a->acinfo->holder->baseid->serial = holdserial;
  a->acinfo->serial = serial;
  a->acinfo->version = version;
  a->acinfo->validity->notBefore = time1;
  a->acinfo->validity->notAfter  = time2;
  a->acinfo->id = uid;
  X509_ALGOR_free(a->acinfo->alg);
  a->acinfo->alg = alg1;
  X509_ALGOR_free(a->sig_alg);
  a->sig_alg = alg2;

  ASN1_sign((int (*)())i2d_AC_INFO, a->acinfo->alg, a->sig_alg, a->signature,
	    (char *)a->acinfo, pkey, EVP_md5());

  *ac = a;
  return 0;
 err:

  X509_EXTENSION_free(auth);
  X509_EXTENSION_free(norevavail);
  X509_EXTENSION_free(targets);
  X509_NAME_free(subjdup);
  X509_NAME_free(issdup);
  GENERAL_NAME_free(dirn);
  GENERAL_NAME_free(dirn2);
  ASN1_INTEGER_free(holdserial);
  ASN1_INTEGER_free(serial);
  AC_ATTR_free(capabilities);
  ASN1_OBJECT_free(cobj);
  AC_IETFATTR_free(capnames);
  ASN1_UTCTIME_free(time1);
  ASN1_UTCTIME_free(time2);

  return err;
}
