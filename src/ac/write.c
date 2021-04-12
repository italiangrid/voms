
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
#include <openssl/asn1t.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/bn.h>
#include <string.h>
#include <assert.h>

#include "newformat.h"
#include "acerrors.h"
#include "attributes.h"
#include "doio.h"
#include "ssl_compat.h"

#define ERROR(e) do { err = (e); goto err; } while (0)

void add_no_rev_avail_ext(AC *ac) {

  X509_EXTENSION* ext = X509V3_EXT_i2d(NID_no_rev_avail,0, ASN1_NULL_new());

  assert( ext != NULL);

  sk_X509_EXTENSION_push(ac->acinfo->exts, ext);

}

int add_authority_key_id_ext(AC *ac, X509* issuer_cert) {

  X509V3_CTX ctx;
  X509V3_set_ctx(&ctx, issuer_cert, NULL, NULL, NULL, 0);
  X509_EXTENSION* ext = X509V3_EXT_conf(NULL, &ctx, "authorityKeyIdentifier", "keyid:always");
  if (!ext) {
    return AC_ERR_NO_EXTENSION;
  }
  sk_X509_EXTENSION_push(ac->acinfo->exts, ext);
  return 0;
}

AC_TARGET* build_ac_target(char* t){

    AC_TARGET *target = AC_TARGET_new();
    ASN1_IA5STRING *target_str = ASN1_IA5STRING_new();

    if (! target || !target_str) {
        AC_TARGET_free(target);
        ASN1_IA5STRING_free(target_str);
        return NULL;
    }

    ASN1_STRING_set(target_str, t, strlen(t));

    GENERAL_NAME *name = target->name;

    name->type = GEN_URI;
    name->d.ia5 = target_str;

    return target;
}

AC_TARGETS* build_ac_targets_ext(char* targets) {

  const char* DELIMITER = ",";
  char *targets_copy = strdup(targets);
  char *token;

  AC_TARGETS* result = AC_TARGETS_new();

  if (! targets_copy || !result ){
    goto err;
  }

  token = strtok(targets_copy, DELIMITER);

  while (token != NULL){

    AC_TARGET *target = build_ac_target(token);

    if (! target ) {
        goto err;
    }

    sk_AC_TARGET_push(result->targets, target);
    token = strtok(NULL, DELIMITER);
  }

  free(targets_copy);
  return result;

err:
  
  if (result) {
    AC_TARGETS_free(result);
  }

  return NULL;
}

int add_targets_ext(AC* ac, char* targets_str) {

  AC_TARGETS *targets = build_ac_targets_ext(targets_str);

  if (!targets) {
    return AC_ERR_NO_EXTENSION;
  }

  X509_EXTENSION* ext = X509V3_EXT_i2d(NID_target_information,1, targets);

  if (!ext) {
    return AC_ERR_NO_EXTENSION;
  }

  sk_X509_EXTENSION_push(ac->acinfo->exts, ext);

  return 0;
}

static int make_and_push_ext(AC *ac, char *name, char *data, int critical)
{

  int ext_NID = OBJ_txt2nid(name);

  if (ext_NID == NID_undef ){
    return AC_ERR_NO_EXTENSION;
  }

  X509_EXTENSION *ext = X509V3_EXT_conf_nid(NULL, NULL, ext_NID, data);

  if (!ext) {
    return AC_ERR_NO_EXTENSION;
  }

  X509_EXTENSION_set_critical(ext, critical);
  sk_X509_EXTENSION_push(ac->acinfo->exts, ext);
  return 0;
}

static void make_uri(const char *vo, const char *uri, STACK_OF(GENERAL_NAME) *names)
{
  GENERAL_NAME   *g    = NULL;
  ASN1_IA5STRING *tmpr = NULL;

  if (vo || uri) {
    char *buffer=snprintf_wrap("%s://%s", vo ? vo : "", uri ? uri : "");

    g = GENERAL_NAME_new();
    tmpr = ASN1_IA5STRING_new();

    if (!tmpr || !g || !buffer) {
      GENERAL_NAME_free(g);
      ASN1_IA5STRING_free(tmpr);
      free(buffer);
      return;
    }

    ASN1_STRING_set(tmpr, buffer, strlen(buffer));
    free(buffer);
    g->type  = GEN_URI;
    g->d.ia5 = tmpr;
    sk_GENERAL_NAME_push(names, g);
  }
}

int writeac(X509 *issuerc, STACK_OF(X509) *issuerstack, X509 *holder, EVP_PKEY *pkey, BIGNUM *s,
            char **fqan, char *t, char **attributes_strings, AC **ac,
            const char *vo, const char *uri, int valid, int old, int startpast,
            STACK_OF(X509_EXTENSION) *extensions)
{
  AC *a;
  X509_NAME *name1, *name2, *subjdup, *issdup;
  GENERAL_NAME *dirn, *dirn2;
  ASN1_INTEGER  *serial, *holdserial, *version;
  ASN1_BIT_STRING *uid;
  AC_ATTR *capabilities;
  AC_IETFATTR *capnames;
  AC_FULL_ATTRIBUTES *ac_full_attrs;
  ASN1_OBJECT *cobj;
  X509_ALGOR *alg1, *alg2;
  ASN1_GENERALIZEDTIME *time1, *time2;
  AC_ATT_HOLDER *ac_att_holder = NULL;
  STACK_OF(X509) *stk = NULL;
  
  ASN1_NULL *null;
  int i = 0;
  int err = AC_ERR_UNKNOWN;
  int ret = 0;

  time_t curtime;

  a = NULL;
  subjdup = issdup = NULL;
  dirn = dirn2 = NULL;
  serial = holdserial = NULL;
  time1 = time2 = NULL;
  uid = NULL;
  capabilities = NULL;
  capnames = NULL;
  cobj = NULL;
  ac_full_attrs = NULL;

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
  holdserial          = ASN1_INTEGER_dup(X509_get_serialNumber(holder));
  serial              = BN_to_ASN1_INTEGER(s, NULL);
  version             = ASN1_INTEGER_new();
  capabilities        = AC_ATTR_new();
  cobj                = OBJ_txt2obj("idatcap",0);
  capnames            = AC_IETFATTR_new();
  null                = ASN1_NULL_new();
  ac_full_attrs       = AC_FULL_ATTRIBUTES_new();
  ac_att_holder       = AC_ATT_HOLDER_new();

  
  if (!subjdup || !issdup || !dirn || !dirn2 || !holdserial || !serial || !version ||
      !capabilities || !cobj || !capnames || !time1 || !time2 ||
      !null || !ac_full_attrs || !ac_att_holder)
    ERROR(AC_ERR_MEMORY);

  ASN1_INTEGER_set(version,1);

  if (capnames->names == NULL) {
    capnames->names = GENERAL_NAMES_new();

    if (capnames->names == NULL){
      ERROR(AC_ERR_MEMORY);
    }
  }

  /* prepare AC_IETFATTR */
  while(fqan[i]) {
    ASN1_OCTET_STRING *tmpc = ASN1_OCTET_STRING_new();

    if (!tmpc) {
      ERROR(AC_ERR_MEMORY);
    }

    ASN1_OCTET_STRING_set(tmpc, (unsigned char*)fqan[i], strlen(fqan[i]));
    sk_AC_IETFATTRVAL_push(capnames->values, tmpc);
    i++;
  }

  if (vo || uri) {
    make_uri(vo, uri, capnames->names);

    sk_AC_IETFATTR_push(capabilities->ietfattr, capnames);
    capnames = NULL;
  }

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

  if (!i) {
    AC_ATT_HOLDER_free(ac_att_holder);
    ac_att_holder = NULL;
  } else {
    make_uri(vo, uri,  ac_att_holder->grantor);
    sk_AC_ATT_HOLDER_push(ac_full_attrs->providers, ac_att_holder);
  }  
  
  /* push both AC_ATTR into STACK_OF(AC_ATTR) */
  sk_AC_ATTR_push(a->acinfo->attrib, capabilities);
  capabilities = NULL;

  if (ac_full_attrs && i) {
    ret = make_and_push_ext(a, "attributes", (char *)(ac_full_attrs->providers), 0);
    AC_FULL_ATTRIBUTES_free(ac_full_attrs);
    ac_full_attrs = NULL;
    ac_att_holder = NULL;

    if (ret)
      ERROR(AC_ERR_NO_EXTENSION);
  } else {
    AC_FULL_ATTRIBUTES_free(ac_full_attrs);
    ac_full_attrs = NULL;
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

  if (ret) {
    ERROR(AC_ERR_NO_EXTENSION);
  }

  /* Create several extensions */
  add_no_rev_avail_ext(a);

  if (add_authority_key_id_ext(a,issuerc)){
    ERROR(AC_ERR_NO_EXTENSION);
  }

  if (t && add_targets_ext(a,t)){
    ERROR(AC_ERR_NO_EXTENSION);
  }

  if (extensions) {
    int proxyindex = 0;

    for (proxyindex = 0; proxyindex < sk_X509_EXTENSION_num(extensions); proxyindex++) {
      X509_EXTENSION *ext = X509_EXTENSION_dup(sk_X509_EXTENSION_value(extensions, i));
      if (ext) {
        if (!sk_X509_EXTENSION_push(a->acinfo->exts, ext)) {
          X509_EXTENSION_free(ext);
          goto err;
        }
      }
      else {
        goto err;
      }
    }
  }

  alg1 = X509_ALGOR_dup((X509_ALGOR*)X509_get0_tbs_sigalg(issuerc));
  {
    X509_ALGOR /*const*/* sig_alg;
    X509_get0_signature(NULL, &sig_alg, issuerc);
    alg2 = X509_ALGOR_dup((X509_ALGOR*)sig_alg);
  }

  {
    ASN1_BIT_STRING const* issuerUID;
    X509_get0_uids(issuerc, &issuerUID, NULL);
    if (issuerUID)
      if (!(uid = ASN1_STRING_dup(issuerUID)))
        ERROR(AC_ERR_MEMORY);
  }

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
  sk_GENERAL_NAME_push(a->acinfo->form, dirn2);
  a->acinfo->id = uid;

  /* Use same signature algorithm used to sign the certificate */
  EVP_MD const* md = EVP_get_digestbyobj(a->sig_alg->algorithm);

  if (md == NULL){
    /* fall back to SHA1 */
    md = EVP_sha1();
  }

  ASN1_sign((int (*)())i2d_AC_INFO, a->acinfo->alg, a->sig_alg, a->signature,
	    (char *)a->acinfo, pkey, md);

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
