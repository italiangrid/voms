
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
#include "attributes.h"

#define ERROR(e) do { err = (e); goto err; } while (0)

static int make_and_push_ext(AC *ac, char *name, char *data, int critical)
{
  X509_EXTENSION *ext = X509V3_EXT_conf_nid(NULL, NULL, OBJ_txt2nid(name), data);

  if (ext) {
    X509_EXTENSION_set_critical(ext, critical);
    sk_X509_EXTENSION_push(ac->acinfo->exts, ext);
    return 0;
  }

  return AC_ERR_NO_EXTENSION;
}

static void make_uri(const char *vo, const char *uri, STACK_OF(GENERAL_NAME) *names)
{
  GENERAL_NAME   *g    = NULL;
  ASN1_IA5STRING *tmpr = NULL;

  if (vo || uri) {
    int len = (vo ? strlen(vo) : 0) +
      (uri ? strlen(uri) : 0) + 4;
    char *buffer=(char *)malloc(len);

    g = GENERAL_NAME_new();
    tmpr = ASN1_IA5STRING_new();

    if (!tmpr || !g || !buffer) {
      GENERAL_NAME_free(g);
      ASN1_IA5STRING_free(tmpr);
      free(buffer);
      return;
    }

    /* Note: the buffer is *always* large enough to accomodate
       the whole string.
    */
    (void)snprintf(buffer, len, "%s://%s", vo ? vo : "",
                   uri ? uri : "");

    ASN1_STRING_set(tmpr, buffer, strlen(buffer));
    free(buffer);
    g->type  = GEN_URI;
    g->d.ia5 = tmpr;
    sk_GENERAL_NAME_push(names, g);
  }
}

int writeac(X509 *issuerc, STACK_OF(X509) *issuerstack, X509 *holder, EVP_PKEY *pkey, BIGNUM *s,
            char **fqan, char *t, char **attributes_strings, AC **ac,
            const char *vo, const char *uri, int valid, int old, int startpast)
{
  AC *a;
  X509_NAME *name1, *name2, *subjdup, *issdup;
  GENERAL_NAME *dirn, *dirn2;
  ASN1_INTEGER  *serial, *holdserial, *version;
  ASN1_BIT_STRING *uid;
  AC_ATTR *capabilities;
  AC_IETFATTR *capnames;
  AC_FULL_ATTRIBUTES *ac_full_attrs;
  ASN1_OBJECT *cobj, *aobj;
  X509_ALGOR *alg1, *alg2;
  ASN1_GENERALIZEDTIME *time1, *time2;
  AC_ATT_HOLDER *ac_att_holder = NULL;
  char *qual, *name, *value, *tmp, *tmp2;
  STACK_OF(X509) *stk = NULL;
  
  ASN1_NULL *null;
  int i = 0;
  int err = AC_ERR_UNKNOWN;
  int ret = 0;

  time_t curtime;

  a = NULL;
  name1 = name2 = subjdup = issdup = NULL;
  dirn = dirn2 = NULL;
  version = serial = holdserial = NULL;
  time1 = time2 = NULL;
  uid = NULL;
  capabilities = NULL;
  capnames = NULL;
  cobj = aobj = NULL;
  ac_full_attrs = NULL;
  qual = name = value = tmp = tmp2 = NULL;

  if (!issuerc || !holder || !s || !fqan || !ac || !pkey)
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
  time1 = ASN1_GENERALIZEDTIME_set(NULL, curtime - startpast);
  time2 = ASN1_GENERALIZEDTIME_set(NULL, curtime + valid - startpast);

  subjdup             = X509_NAME_dup(name2);
  issdup              = X509_NAME_dup(name1);
  dirn                = GENERAL_NAME_new();
  dirn2               = GENERAL_NAME_new();
  holdserial          = M_ASN1_INTEGER_dup(holder->cert_info->serialNumber);
  serial              = BN_to_ASN1_INTEGER(s, NULL);
  version             = BN_to_ASN1_INTEGER((BIGNUM *)(BN_value_one()), NULL);
  capabilities        = AC_ATTR_new();
  cobj                = OBJ_txt2obj("idatcap",0);
  aobj                = OBJ_txt2obj("attributes",0);
  capnames            = AC_IETFATTR_new();
  null                = ASN1_NULL_new();
  ac_full_attrs       = AC_FULL_ATTRIBUTES_new();
  ac_att_holder       = AC_ATT_HOLDER_new();

  if (!subjdup || !issdup || !dirn || !dirn2 || !holdserial || !serial ||
      !capabilities || !cobj || !capnames || !time1 || !time2 ||
      !null || !ac_full_attrs || !ac_att_holder)
    ERROR(AC_ERR_MEMORY);

  /* prepare AC_IETFATTR */
  while(fqan[i]) {
    ASN1_OCTET_STRING *tmpc = ASN1_OCTET_STRING_new();
    if (!tmpc) {
      ASN1_OCTET_STRING_free(tmpc);
      ERROR(AC_ERR_MEMORY);
    }
    ASN1_OCTET_STRING_set(tmpc, (unsigned char*)fqan[i], strlen(fqan[i]));
    sk_AC_IETFATTRVAL_push(capnames->values, (AC_IETFATTRVAL *)tmpc);
    i++;
  }

  if (vo || uri) {
    make_uri(vo, uri, capnames->names);

    /* stuff the created AC_IETFATTR in ietfattr (values) and define its object */
    sk_AC_IETFATTR_push(capabilities->ietfattr, capnames);
    capnames = NULL;
  }

  capabilities->get_type = GET_TYPE_FQAN;
  ASN1_OBJECT_free(capabilities->type);
  capabilities->type = cobj;

  i = 0;
  /* prepare AC_FULL_ATTRIBUTES */
  if (attributes_strings) {
    while (attributes_strings[i]) {
      char *qual, *name, *value;
      char *tmp = NULL, *tmp2 = NULL;

      AC_ATTRIBUTE *ac_attr      = AC_ATTRIBUTE_new();

      if (!ac_attr) {
        AC_ATTRIBUTE_free(ac_attr);
        ERROR(AC_ERR_MEMORY);
      }

      tmp = strstr(attributes_strings[i], "::");
      if (tmp == attributes_strings[i]) {
        qual = NULL;
        tmp = attributes_strings[i] + 2;
      }
      else {
        *tmp='\0';
        qual = attributes_strings[i];
        tmp += 2;
      }

      tmp2 = strstr(tmp, "=");
      if (!tmp2) {
        ERROR(AC_ERR_PARAMETERS);
      }
      else {
        name = tmp;
        *tmp2 = '\0';
        value = ++tmp2;
      }

      if (qual)
        ASN1_OCTET_STRING_set(ac_attr->qualifier, (unsigned char *)qual, strlen(qual));
      else if (vo)
        ASN1_OCTET_STRING_set(ac_attr->qualifier, (unsigned char *)vo, strlen(vo));
      else
        ASN1_OCTET_STRING_set(ac_attr->qualifier, (unsigned char *)"", 0);
      
      ASN1_OCTET_STRING_set(ac_attr->name,        (unsigned char *)name,  strlen(name));
      ASN1_OCTET_STRING_set(ac_attr->value,       (unsigned char *)value, strlen(value));
      
      sk_AC_ATTRIBUTE_push(ac_att_holder->attributes, ac_attr);
      i++;
    }
  }

  if (!i) 
    AC_ATT_HOLDER_free(ac_att_holder);
  else {
    make_uri(vo, uri,  ac_att_holder->grantor);
    sk_AC_ATT_HOLDER_push(ac_full_attrs->providers, ac_att_holder);
  }  
  
  /* push both AC_ATTR into STACK_OF(AC_ATTR) */
  sk_AC_ATTR_push(a->acinfo->attrib, capabilities);
  capabilities = NULL;

  if (ac_full_attrs) {
    ret = make_and_push_ext(a, "attributes", (char *)(ac_full_attrs->providers), 0);
    AC_FULL_ATTRIBUTES_free(ac_full_attrs);
    ac_full_attrs = NULL;
    ac_att_holder = NULL;

    if (ret)
      ERROR(AC_ERR_NO_EXTENSION);
  }

  stk = sk_X509_new_null();

  if (issuerstack) {
    for (i =0; i < sk_X509_num(issuerstack); i++)
      sk_X509_push(stk, X509_dup(sk_X509_value(issuerstack, i)));
  }

#ifdef TYPEDEF_I2D_OF
  sk_X509_push(stk,
               (X509 *)ASN1_dup((i2d_of_void*)i2d_X509,(d2i_of_void*)d2i_X509, (char *)issuerc));
#else
  sk_X509_push(stk,
               (X509 *)ASN1_dup((int (*)())i2d_X509,(char * (*)())d2i_X509, (char *)issuerc));
#endif

  ret = make_and_push_ext(a, "certseq", (char*)stk, 0);
  sk_X509_pop_free(stk, X509_free);

  if (ret)
    ERROR(AC_ERR_NO_EXTENSION);

  /* Create several extensions */
  if (make_and_push_ext(a, "idcenoRevAvail", "loc", 0) ||
      make_and_push_ext(a, "authKeyId", (char *)issuerc, 0) ||
      (t && make_and_push_ext(a, "idceTargets", t, 1)))
    ERROR(AC_ERR_NO_EXTENSION);

  alg1 = X509_ALGOR_dup(issuerc->cert_info->signature);
  alg2 = X509_ALGOR_dup(issuerc->sig_alg);

  if (issuerc->cert_info->issuerUID)
    if (!(uid = M_ASN1_BIT_STRING_dup(issuerc->cert_info->issuerUID)))
      ERROR(AC_ERR_MEMORY);

#define FREE_AND_SET(datum, value, type) type##_free((datum)); (datum) = (value)

  FREE_AND_SET(a->acinfo->holder->baseid->serial, holdserial, ASN1_INTEGER);
  FREE_AND_SET(a->acinfo->serial, serial, ASN1_INTEGER);
  FREE_AND_SET(a->acinfo->version, version, ASN1_INTEGER);
  FREE_AND_SET(a->acinfo->validity->notBefore, time1, ASN1_GENERALIZEDTIME);
  FREE_AND_SET(a->acinfo->validity->notAfter, time2, ASN1_GENERALIZEDTIME);
  FREE_AND_SET(a->acinfo->alg, alg1, X509_ALGOR);
  FREE_AND_SET(a->sig_alg, alg2, X509_ALGOR);

#undef FREE_AND_SET

  dirn->d.dirn = subjdup;
  dirn->type = GEN_DIRNAME;
  sk_GENERAL_NAME_push(a->acinfo->holder->baseid->issuer, dirn);
  dirn2->d.dirn = issdup;
  dirn2->type = GEN_DIRNAME;
  sk_GENERAL_NAME_push(a->acinfo->form->names, dirn2);
  a->acinfo->id = uid;

  ASN1_sign((int (*)())i2d_AC_INFO, a->acinfo->alg, a->sig_alg, a->signature,
	    (char *)a->acinfo, pkey, EVP_sha1());

  *ac = a;
  return 0;

 err:
  sk_X509_EXTENSION_pop_free(a->acinfo->exts, X509_EXTENSION_free);
  a->acinfo->exts = NULL;
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
  AC_ATT_HOLDER_free(ac_att_holder);
  AC_FULL_ATTRIBUTES_free(ac_full_attrs);
  return err;
}
