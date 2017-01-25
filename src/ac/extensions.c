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

#include <stdlib.h>

#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/err.h>
#include <openssl/asn1.h>
#include <openssl/stack.h>
#include <openssl/safestack.h>
#include <openssl/objects.h>
#include <openssl/pem.h>

#include "newformat.h"
#include "acerrors.h"
#include "attributes.h"
#include <string.h>
#include <assert.h>

#ifndef VOMS_MAYBECONST
#if defined(D2I_OF)
#define VOMS_MAYBECONST const
#else
#define VOMS_MAYBECONST
#endif
#endif

static char *norep()
{
  static char *buffer = 0;
  buffer = (char *) malloc(1);
  if (buffer)
    *buffer='\0';
  
  return buffer;
}

char *acseq_i2s(UNUSED(struct v3_ext_method *method), UNUSED(void *ext))
{
  return norep();
}
  
char *targets_i2s(UNUSED(struct v3_ext_method *method), UNUSED(void *ext))
{
  return norep();
}

char *certs_i2s(UNUSED(struct v3_ext_method *method), UNUSED(void *ext))
{
  return norep();
}

char *null_i2s(UNUSED(struct v3_ext_method *method), UNUSED(void *ext))
{
  return norep();
}

char *attributes_i2s(UNUSED(struct v3_ext_method *method), UNUSED(void *ext))
{
  return norep();
}

void *acseq_s2i(UNUSED(struct v3_ext_method *method), UNUSED(struct v3_ext_ctx *ctx), char *data)
{
  AC **list = (AC **)data;
  AC_SEQ *a;

  if (!list) return NULL;

  a = AC_SEQ_new();

  while (*list)
    sk_AC_push(a->acs, *list++);

  return (void *)a;
}

void *targets_s2i(UNUSED(struct v3_ext_method *method), UNUSED(struct v3_ext_ctx *ctx), char *data)
{
  char *pos;
  char *list = strdup(data);
  char *back = list;
  AC_TARGETS *a = AC_TARGETS_new();

  int attlist;
  do {
    pos = strchr(list, ',');

    if (pos)
      *pos = '\0';
    {
      GENERAL_NAME *g = GENERAL_NAME_new();
      ASN1_IA5STRING *tmpr = ASN1_IA5STRING_new();
      AC_TARGET *targ = AC_TARGET_new();

      if (!g || !tmpr || !targ) {
        GENERAL_NAME_free(g);
        ASN1_IA5STRING_free(tmpr);
        AC_TARGET_free(targ);
        goto err;
      }
      ASN1_STRING_set(tmpr, list, strlen(list));
      g->type = GEN_URI;
      g->d.ia5 = tmpr;
      targ->name = g;
      sk_AC_TARGET_push(a->targets, targ);
      attlist++;
    }
    if (pos)
      list = ++pos;
  } while (pos);

  free(back);
  return a;

 err:
  free(back);
  AC_TARGETS_free(a);
  return NULL;    

}

void *certs_s2i(UNUSED(struct v3_ext_method *method), UNUSED(struct v3_ext_ctx *ctx), char *data)
{
  STACK_OF(X509) *certs =
    (STACK_OF(X509) *)data;
  int i = 0;

  if (data) {
    AC_CERTS *a = AC_CERTS_new();

    sk_X509_pop_free(a->stackcert, X509_free);
    a->stackcert = sk_X509_new_null();

/*     a->stackcert = sk_X509_dup(certs); */
    for (i =0; i < sk_X509_num(certs); i++)
      sk_X509_push(a->stackcert, X509_dup(sk_X509_value(certs, i)));

    return a;
  }

  return NULL;    
}

void *attributes_s2i(UNUSED(struct v3_ext_method *method), UNUSED(struct v3_ext_ctx *ctx), char *data)
{
  int i = 0;

  STACK_OF(AC_ATT_HOLDER) *stack =
    (STACK_OF(AC_ATT_HOLDER) *)data;

  if (data) {
    AC_FULL_ATTRIBUTES *a = AC_FULL_ATTRIBUTES_new();
    sk_AC_ATT_HOLDER_pop_free(a->providers, AC_ATT_HOLDER_free);
    a->providers = sk_AC_ATT_HOLDER_new_null();
/*     a->providers = sk_AC_ATT_HOLDER_dup(stack); */
    for (i = 0; i < sk_AC_ATT_HOLDER_num(stack); i++) 
      sk_AC_ATT_HOLDER_push(a->providers,
                            (AC_ATT_HOLDER *)ASN1_dup((i2d_of_void*)i2d_AC_ATT_HOLDER,
                                                      (d2i_of_void*)d2i_AC_ATT_HOLDER,
                                                      sk_AC_ATT_HOLDER_value(stack, i)));

    
    return a;
  }
  return NULL;
}

void *null_s2i(UNUSED(struct v3_ext_method *method), UNUSED(struct v3_ext_ctx *ctx), UNUSED(char *data))
{
  return ASN1_NULL_new();
}

char *authkey_i2s(UNUSED(struct v3_ext_method *method), UNUSED(void *ext))
{
  return norep();
}

void *authkey_s2i(UNUSED(struct v3_ext_method *method), UNUSED(struct v3_ext_ctx *ctx), char *data)
{
  X509       *cert = (X509 *)data;
  unsigned char digest[21];

  ASN1_OCTET_STRING *str = ASN1_OCTET_STRING_new();
  AUTHORITY_KEYID *keyid = AUTHORITY_KEYID_new();

  if (str && keyid) {
    X509_PUBKEY* pk = X509_get_X509_PUBKEY(cert);
    assert(pk != NULL && "X509_get_X509_PUBKEY failed");
    unsigned char const* data;
    int len;
    int e = X509_PUBKEY_get0_param(NULL, &data, &len, NULL, pk);
    assert(e == 1 && "X509_PUBKEY_get0_param failed");
    SHA1(data, len, digest);
    ASN1_OCTET_STRING_set(str, digest, 20);
    ASN1_OCTET_STRING_free(keyid->keyid);
    keyid->keyid = str;
  }
  else {
    if (str) ASN1_OCTET_STRING_free(str);
    if (keyid) AUTHORITY_KEYID_free(keyid);
    keyid = NULL;
  }
  return keyid;
}

int initEx(void)
{
  X509V3_EXT_METHOD *targets;
  X509V3_EXT_METHOD *avail;
  X509V3_EXT_METHOD *auth;
  X509V3_EXT_METHOD *acseq;
  X509V3_EXT_METHOD *certseq;
  X509V3_EXT_METHOD *attribs;

  avail   = (X509V3_EXT_METHOD *)OPENSSL_malloc(sizeof(X509V3_EXT_METHOD));
  targets = (X509V3_EXT_METHOD *)OPENSSL_malloc(sizeof(X509V3_EXT_METHOD));
  auth    = (X509V3_EXT_METHOD *)OPENSSL_malloc(sizeof(X509V3_EXT_METHOD));
  acseq   = (X509V3_EXT_METHOD *)OPENSSL_malloc(sizeof(X509V3_EXT_METHOD));
  certseq = (X509V3_EXT_METHOD *)OPENSSL_malloc(sizeof(X509V3_EXT_METHOD));
  attribs = (X509V3_EXT_METHOD *)OPENSSL_malloc(sizeof(X509V3_EXT_METHOD));

  if (!avail || !targets || !auth || !acseq || !certseq || !attribs) {
    OPENSSL_free(avail);
    OPENSSL_free(targets);
    OPENSSL_free(auth);
    OPENSSL_free(acseq);
    OPENSSL_free(certseq);
    OPENSSL_free(attribs);
    return 0;
  }

#ifndef VOMS_USE_OPENSSL_EXT_CODE
  memset(auth, 0, sizeof(*auth));

  auth->ext_nid  = OBJ_txt2nid("authorityKeyIdentifier");

  auth->ext_flags = 0;
  auth->ext_new  = (X509V3_EXT_NEW) AUTHORITY_KEYID_new;
  auth->ext_free = (X509V3_EXT_FREE)AUTHORITY_KEYID_free;
  auth->d2i      = (X509V3_EXT_D2I) d2i_AUTHORITY_KEYID;
  auth->i2d      = (X509V3_EXT_I2D) i2d_AUTHORITY_KEYID;
  auth->i2s      = (X509V3_EXT_I2S) authkey_i2s;
  auth->s2i      = (X509V3_EXT_S2I) authkey_s2i;
  auth->v2i      = (X509V3_EXT_V2I) NULL;
  auth->r2i      = (X509V3_EXT_R2I) NULL;
  auth->i2v      = (X509V3_EXT_I2V) NULL;
  auth->i2r      = (X509V3_EXT_I2R) NULL;

  X509V3_EXT_add(auth);

  memset(avail, 0, sizeof(*avail));
  avail->ext_nid  = OBJ_txt2nid("noRevAvail");
  avail->ext_flags = 0;
  avail->ext_new  = (X509V3_EXT_NEW) ASN1_NULL_new;
  avail->ext_free = (X509V3_EXT_FREE)ASN1_NULL_free;
  avail->d2i      = (X509V3_EXT_D2I) d2i_ASN1_NULL;
  avail->i2d      = (X509V3_EXT_I2D) i2d_ASN1_NULL;
  avail->i2s      = (X509V3_EXT_I2S) NULL;
  avail->s2i      = (X509V3_EXT_S2I) NULL;
  avail->v2i      = (X509V3_EXT_V2I) NULL;
  avail->r2i      = (X509V3_EXT_R2I) NULL;
  avail->i2v      = (X509V3_EXT_I2V) NULL;
  avail->i2r      = (X509V3_EXT_I2R) NULL;

  X509V3_EXT_add(avail);

  memset(targets, 0, sizeof(*targets));
  targets->ext_nid  = OBJ_txt2nid("targetInformation");
  targets->ext_flags = 0;
  targets->ext_new  = (X509V3_EXT_NEW) AC_TARGETS_new;
  targets->ext_free = (X509V3_EXT_FREE)AC_TARGETS_free;
  targets->d2i      = (X509V3_EXT_D2I) d2i_AC_TARGETS;
  targets->i2d      = (X509V3_EXT_I2D) i2d_AC_TARGETS;
  targets->s2i      = (X509V3_EXT_S2I) targets_s2i;
  targets->i2s      = (X509V3_EXT_I2S) targets_i2s;
  targets->i2v      = (X509V3_EXT_I2V) NULL;
  targets->v2i      = (X509V3_EXT_V2I) NULL;
  targets->r2i      = (X509V3_EXT_R2I) NULL;
  targets->i2r      = (X509V3_EXT_I2R) NULL;
#endif

  X509V3_EXT_add(targets);

  memset(acseq, 0, sizeof(*acseq));
  acseq->ext_nid  = OBJ_txt2nid("acseq");
  acseq->ext_flags = 0;
  acseq->ext_new  = (X509V3_EXT_NEW) AC_SEQ_new;
  acseq->ext_free = (X509V3_EXT_FREE)AC_SEQ_free;
  acseq->d2i      = (X509V3_EXT_D2I) d2i_AC_SEQ;
  acseq->i2d      = (X509V3_EXT_I2D) i2d_AC_SEQ;
  acseq->s2i      = (X509V3_EXT_S2I) acseq_s2i;
  acseq->i2s      = (X509V3_EXT_I2S) acseq_i2s;
  acseq->i2v      = (X509V3_EXT_I2V) NULL;
  acseq->v2i      = (X509V3_EXT_V2I) NULL;
  acseq->r2i      = (X509V3_EXT_R2I) NULL;
  acseq->i2r      = (X509V3_EXT_I2R) NULL;

  X509V3_EXT_add(acseq);

  memset(certseq, 0, sizeof(*certseq));
  certseq->ext_nid  = OBJ_txt2nid("certseq");
  certseq->ext_flags = 0;
  certseq->ext_new  = (X509V3_EXT_NEW) AC_CERTS_new;
  certseq->ext_free = (X509V3_EXT_FREE)AC_CERTS_free;
  certseq->d2i      = (X509V3_EXT_D2I) d2i_AC_CERTS;
  certseq->i2d      = (X509V3_EXT_I2D) i2d_AC_CERTS;
  certseq->s2i      = (X509V3_EXT_S2I) certs_s2i;
  certseq->i2s      = (X509V3_EXT_I2S) certs_i2s;
  certseq->i2v      = (X509V3_EXT_I2V) NULL;
  certseq->v2i      = (X509V3_EXT_V2I) NULL;
  certseq->r2i      = (X509V3_EXT_R2I) NULL;
  certseq->i2r      = (X509V3_EXT_I2R) NULL;

  X509V3_EXT_add(certseq);

  memset(attribs, 0, sizeof(*attribs));
  attribs->ext_nid  = OBJ_txt2nid("attributes");
  attribs->ext_flags = 0;
  attribs->ext_new  = (X509V3_EXT_NEW) AC_FULL_ATTRIBUTES_new;
  attribs->ext_free = (X509V3_EXT_FREE)AC_FULL_ATTRIBUTES_free;
  attribs->d2i      = (X509V3_EXT_D2I) d2i_AC_FULL_ATTRIBUTES;
  attribs->i2d      = (X509V3_EXT_I2D) i2d_AC_FULL_ATTRIBUTES;
  attribs->s2i      = (X509V3_EXT_S2I) attributes_s2i;
  attribs->i2s      = (X509V3_EXT_I2S) attributes_i2s;
  attribs->i2v      = (X509V3_EXT_I2V) NULL;
  attribs->v2i      = (X509V3_EXT_V2I) NULL;
  attribs->r2i      = (X509V3_EXT_R2I) NULL;
  attribs->i2r      = (X509V3_EXT_I2R) NULL;

  X509V3_EXT_add(attribs);

  return 1;
}
