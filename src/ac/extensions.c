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

#include <stdlib.h>

#include <openssl/evp.h>
#include <openssl/asn1_mac.h>
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

int i2d_AC_SEQ(AC_SEQ *a, unsigned char **pp)
{
  M_ASN1_I2D_vars(a);
  M_ASN1_I2D_len_SEQUENCE(a->acs, i2d_AC);
  M_ASN1_I2D_seq_total();
  M_ASN1_I2D_put_SEQUENCE(a->acs, i2d_AC);
  M_ASN1_I2D_finish();
}

AC_SEQ *d2i_AC_SEQ(AC_SEQ **a, unsigned char **pp, long length)
{
  M_ASN1_D2I_vars(a, AC_SEQ *, AC_SEQ_new);

  M_ASN1_D2I_Init();
  M_ASN1_D2I_start_sequence();
  M_ASN1_D2I_get_seq(ret->acs, d2i_AC, AC_free);
  M_ASN1_D2I_Finish(a, AC_SEQ_free, ASN1_F_D2I_AC_SEQ);
}

AC_SEQ *AC_SEQ_new()
{
  AC_SEQ *ret = NULL;
  ASN1_CTX c;

  M_ASN1_New_Malloc(ret, AC_SEQ);
  M_ASN1_New(ret->acs, sk_AC_new_null);
  return ret;
  M_ASN1_New_Error(AC_F_AC_SEQ_new);
}

void AC_SEQ_free(AC_SEQ *a)
{
  if (a==NULL) return;

  sk_AC_pop_free(a->acs, AC_free);
  OPENSSL_free(a);
}

int i2d_AC_TARGETS(AC_TARGETS *a, unsigned char **pp)
{
  M_ASN1_I2D_vars(a);
  M_ASN1_I2D_len_SEQUENCE(a->targets, i2d_AC_TARGET);
  M_ASN1_I2D_seq_total();
  M_ASN1_I2D_put_SEQUENCE(a->targets, i2d_AC_TARGET);
  M_ASN1_I2D_finish();
}
AC_TARGETS *d2i_AC_TARGETS(AC_TARGETS **a, unsigned char **pp, long length)
{
  M_ASN1_D2I_vars(a, AC_TARGETS *, AC_TARGETS_new);

  M_ASN1_D2I_Init();
  M_ASN1_D2I_start_sequence();
  M_ASN1_D2I_get_seq(ret->targets, d2i_AC_TARGET, AC_TARGET_free);
  M_ASN1_D2I_Finish(a, AC_TARGETS_free, ASN1_F_D2I_AC_TARGETS);
}
AC_TARGETS *AC_TARGETS_new()
{
  AC_TARGETS *ret=NULL;
  ASN1_CTX c;

  M_ASN1_New_Malloc(ret, AC_TARGETS);
  M_ASN1_New(ret->targets, sk_AC_TARGET_new_null);
  return ret;
  M_ASN1_New_Error(AC_F_AC_TARGETS_New);
}

void AC_TARGETS_free(AC_TARGETS *a)
{
  if (a==NULL) return;

  sk_AC_TARGET_pop_free(a->targets, AC_TARGET_free);
  OPENSSL_free(a);
}

int i2d_AC_TARGET(AC_TARGET *a, unsigned char **pp)
{
  int v1=0, v2=0, v3=0;

  M_ASN1_I2D_vars(a);
  M_ASN1_I2D_len_EXP_opt(a->name, i2d_GENERAL_NAME, 0, v1);
  M_ASN1_I2D_len_EXP_opt(a->group, i2d_GENERAL_NAME, 1, v2);
  M_ASN1_I2D_len_EXP_opt(a->cert, i2d_AC_IS, 2, v3);
  M_ASN1_I2D_seq_total();

  M_ASN1_I2D_put_EXP_opt(a->name, i2d_GENERAL_NAME, 0, v1);
  M_ASN1_I2D_put_EXP_opt(a->group, i2d_GENERAL_NAME, 1, v2);
  M_ASN1_I2D_put_EXP_opt(a->cert, i2d_AC_IS, 2, v3);
  M_ASN1_I2D_finish();
}

AC_TARGET *d2i_AC_TARGET(AC_TARGET **a, unsigned char **pp, long length)
{
  M_ASN1_D2I_vars(a, AC_TARGET *, AC_TARGET_new);

  M_ASN1_D2I_Init();
  M_ASN1_D2I_start_sequence();
  M_ASN1_D2I_get_EXP_opt(ret->name, d2i_GENERAL_NAME, 0);
  M_ASN1_D2I_get_EXP_opt(ret->group, d2i_GENERAL_NAME, 1);
  M_ASN1_D2I_get_EXP_opt(ret->cert, d2i_AC_IS, 2);
  M_ASN1_D2I_Finish(a, AC_TARGET_free, ASN1_F_D2I_AC_TARGET);
}

AC_TARGET *AC_TARGET_new(void)
{
  AC_TARGET *ret=NULL;
  ASN1_CTX c;

  M_ASN1_New_Malloc(ret, AC_TARGET);
  ret->name = ret->group = NULL;
  ret->cert = NULL;
  return ret;
  M_ASN1_New_Error(AC_F_AC_TARGET_New);
}

void AC_TARGET_free(AC_TARGET *a)
{
  if (a==NULL) return;
  GENERAL_NAME_free(a->name);
  GENERAL_NAME_free(a->group);
  AC_IS_free(a->cert);
  OPENSSL_free(a);
}

int i2d_AC_CERTS(AC_CERTS *a, unsigned char **pp)
{
  int v1=0, v2=0, v3=0;

  M_ASN1_I2D_vars(a);
  M_ASN1_I2D_len_SEQUENCE(a->stackcert, i2d_X509);
  M_ASN1_I2D_seq_total();
  M_ASN1_I2D_put_SEQUENCE(a->stackcert, i2d_X509);
  M_ASN1_I2D_finish();
}

AC_CERTS *d2i_AC_CERTS(AC_CERTS **a, unsigned char **pp, long length)
{
  M_ASN1_D2I_vars(a, AC_CERTS *, AC_CERTS_new);

  M_ASN1_D2I_Init();
  M_ASN1_D2I_start_sequence();
  M_ASN1_D2I_get_seq(ret->stackcert, d2i_X509, X509_free);
  M_ASN1_D2I_Finish(a, AC_CERTS_free, ASN1_F_D2I_AC_CERTS);
}

AC_CERTS *AC_CERTS_new()
{
  AC_CERTS *ret=NULL;
  ASN1_CTX c;

  M_ASN1_New_Malloc(ret, AC_CERTS);
  M_ASN1_New(ret->stackcert, sk_X509_new_null);
  return ret;
  M_ASN1_New_Error(AC_F_X509_New);
}

void AC_CERTS_free(AC_CERTS *a)
{
  if (a==NULL) return;

  sk_X509_pop_free(a->stackcert, X509_free);
  OPENSSL_free(a);
}

int i2d_AC_ATTRIBUTE(AC_ATTRIBUTE *a, unsigned char **pp)
{
  M_ASN1_I2D_vars(a);
  M_ASN1_I2D_len(a->name,      i2d_ASN1_OCTET_STRING);
  M_ASN1_I2D_len(a->value,     i2d_ASN1_OCTET_STRING);
  M_ASN1_I2D_len(a->qualifier, i2d_ASN1_OCTET_STRING);

  M_ASN1_I2D_seq_total();

  M_ASN1_I2D_put(a->name,      i2d_ASN1_OCTET_STRING);
  M_ASN1_I2D_put(a->value,     i2d_ASN1_OCTET_STRING);
  M_ASN1_I2D_put(a->qualifier, i2d_ASN1_OCTET_STRING);

  M_ASN1_I2D_finish();
}

AC_ATTRIBUTE *d2i_AC_ATTRIBUTE(AC_ATTRIBUTE **a, unsigned char **pp, long length)
{
  M_ASN1_D2I_vars(a, AC_ATTRIBUTE *, AC_ATTRIBUTE_new);

  M_ASN1_D2I_Init();
  M_ASN1_D2I_start_sequence();
  M_ASN1_D2I_get(ret->name,      d2i_ASN1_OCTET_STRING);
  M_ASN1_D2I_get(ret->value,     d2i_ASN1_OCTET_STRING);
  M_ASN1_D2I_get(ret->qualifier, d2i_ASN1_OCTET_STRING);

  M_ASN1_D2I_Finish(a, AC_ATTRIBUTE_free, AC_F_D2I_AC_ATTRIBUTE);
}

AC_ATTRIBUTE *AC_ATTRIBUTE_new()
{
  AC_ATTRIBUTE *ret = NULL;
  ASN1_CTX c;
  M_ASN1_New_Malloc(ret, AC_ATTRIBUTE);
  M_ASN1_New(ret->name,      ASN1_OCTET_STRING_new);
  M_ASN1_New(ret->value,     ASN1_OCTET_STRING_new);
  M_ASN1_New(ret->qualifier, ASN1_OCTET_STRING_new);

  return ret;
  M_ASN1_New_Error(AC_F_ATTRIBUTE_New);
}

void AC_ATTRIBUTE_free(AC_ATTRIBUTE *a)
{
  if (a == NULL) return;

  ASN1_OCTET_STRING_free(a->name);
  ASN1_OCTET_STRING_free(a->value);
  ASN1_OCTET_STRING_free(a->qualifier);

  OPENSSL_free(a);
}

int i2d_AC_ATT_HOLDER(AC_ATT_HOLDER *a, unsigned char **pp)
{
  M_ASN1_I2D_vars(a);
  M_ASN1_I2D_len(a->grantor,      i2d_GENERAL_NAMES);
  M_ASN1_I2D_len_SEQUENCE(a->attributes, i2d_AC_ATTRIBUTE);
  M_ASN1_I2D_seq_total();

  M_ASN1_I2D_put(a->grantor,      i2d_GENERAL_NAMES);
  M_ASN1_I2D_put_SEQUENCE(a->attributes, i2d_AC_ATTRIBUTE);
  M_ASN1_I2D_finish();
}


AC_ATT_HOLDER *d2i_AC_ATT_HOLDER(AC_ATT_HOLDER **a, unsigned char **pp, long length)
{
  M_ASN1_D2I_vars(a, AC_ATT_HOLDER *, AC_ATT_HOLDER_new);

  M_ASN1_D2I_Init();
  M_ASN1_D2I_start_sequence();
  M_ASN1_D2I_get(ret->grantor, d2i_GENERAL_NAMES);
  M_ASN1_D2I_get_seq(ret->attributes, d2i_AC_ATTRIBUTE, AC_ATTRIBUTE_free);
  M_ASN1_D2I_Finish(a, AC_ATT_HOLDER_free, ASN1_F_D2I_AC_ATT_HOLDER);
}

AC_ATT_HOLDER *AC_ATT_HOLDER_new()
{
  AC_ATT_HOLDER *ret = NULL;
  ASN1_CTX c;

  M_ASN1_New_Malloc(ret, AC_ATT_HOLDER);
  M_ASN1_New(ret->grantor, sk_GENERAL_NAME_new_null);
  M_ASN1_New(ret->attributes, sk_AC_ATTRIBUTE_new_null);
  return ret;

  M_ASN1_New_Error(AC_F_AC_ATT_HOLDER_New);
}

void AC_ATT_HOLDER_free(AC_ATT_HOLDER *a)
{
  if (a == NULL) return;

  sk_GENERAL_NAME_pop_free(a->grantor, GENERAL_NAME_free);
  sk_AC_ATTRIBUTE_pop_free(a->attributes, AC_ATTRIBUTE_free);
  OPENSSL_free(a);
}

int i2d_AC_FULL_ATTRIBUTES(AC_FULL_ATTRIBUTES *a, unsigned char **pp)
{
  M_ASN1_I2D_vars(a);
  M_ASN1_I2D_len_SEQUENCE(a->providers, i2d_AC_ATT_HOLDER);
  M_ASN1_I2D_seq_total();
  M_ASN1_I2D_put_SEQUENCE(a->providers, i2d_AC_ATT_HOLDER);
  M_ASN1_I2D_finish();
}

AC_FULL_ATTRIBUTES *d2i_AC_FULL_ATTRIBUTES(AC_FULL_ATTRIBUTES **a, unsigned char **pp, long length)
{
  M_ASN1_D2I_vars(a, AC_FULL_ATTRIBUTES *, AC_FULL_ATTRIBUTES_new);

  M_ASN1_D2I_Init();
  M_ASN1_D2I_start_sequence();
  M_ASN1_D2I_get_seq(ret->providers, d2i_AC_ATT_HOLDER, AC_ATT_HOLDER_free);
  M_ASN1_D2I_Finish(a, AC_FULL_ATTRIBUTES_free, ASN1_F_D2I_AC_FULL_ATTRIBUTES);
}

AC_FULL_ATTRIBUTES *AC_FULL_ATTRIBUTES_new()
{
  AC_FULL_ATTRIBUTES *ret = NULL;
  ASN1_CTX c;

  M_ASN1_New_Malloc(ret, AC_FULL_ATTRIBUTES);
  M_ASN1_New(ret->providers, sk_AC_ATT_HOLDER_new_null);
  return ret;
  M_ASN1_New_Error(AC_F_AC_FULL_ATTRIBUTES_New);
}

void AC_FULL_ATTRIBUTES_free(AC_FULL_ATTRIBUTES *a)
{
  if (a == NULL) return;

  sk_AC_ATT_HOLDER_pop_free(a->providers, AC_ATT_HOLDER_free);
  OPENSSL_free(a);
}

IMPL_STACK(AC_ATTRIBUTE)
IMPL_STACK(AC_ATT_HOLDER)
IMPL_STACK(AC_FULL_ATTRIBUTES)


static char *norep()
{
  static char *buffer="";

/*   buffer=malloc(1); */
/*   if (buffer) */
/*     *buffer='\0'; */
  return buffer;

}

char *acseq_i2s(struct v3_ext_method *method, void *ext)
{
  return norep();
}
  
char *targets_i2s(struct v3_ext_method *method, void *ext)
{
  return norep();
}

char *certs_i2s(struct v3_ext_method *method, void *ext)
{
  return norep();
}

char *null_i2s(struct v3_ext_method *method, void *ext)
{
  return norep();
}

char *attributes_i2s(struct v3_ext_method *method, void *ext)
{
  return norep();
}

void *acseq_s2i(struct v3_ext_method *method, struct v3_ext_ctx *ctx, char *data)
{
  AC **list = (AC **)data;
  AC_SEQ *a;

  if (!list) return NULL;

  a = AC_SEQ_new();

  while (*list)
    sk_AC_push(a->acs, *list++);

  return (void *)a;
}

void *targets_s2i(struct v3_ext_method *method, struct v3_ext_ctx *ctx, char *data)
{
  char *pos;
  char *list = strdup(data);
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
      list = pos++;
  } while (pos);

  return a;

 err:
  AC_TARGETS_free(a);
  return NULL;    

}

void *certs_s2i(struct v3_ext_method *method, struct v3_ext_ctx *ctx, char *data)
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

void *attributes_s2i(struct v3_ext_method *method, struct v3_ext_ctx *ctx, char *data)
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
                            (AC_ATT_HOLDER *)ASN1_dup((int (*)())i2d_AC_ATT_HOLDER,
                                                      (char * (*)())d2i_AC_ATT_HOLDER, 
                                                      (char *)(sk_AC_ATT_HOLDER_value(stack, i))));

    
    return a;
  }
  return NULL;
}

void *null_s2i(struct v3_ext_method *method, struct v3_ext_ctx *ctx, char *data)
{
  return ASN1_NULL_new();
}

char *authkey_i2s(struct v3_ext_method *method, void *ext)
{
  return norep();
}

void *authkey_s2i(struct v3_ext_method *method, struct v3_ext_ctx *ctx, char *data)
{
  X509       *cert = (X509 *)data;
  char digest[21];

  ASN1_OCTET_STRING *str = ASN1_OCTET_STRING_new();
  AUTHORITY_KEYID *keyid = AUTHORITY_KEYID_new();

  if (str && keyid) {
    SHA1(cert->cert_info->key->public_key->data,
	 cert->cert_info->key->public_key->length,
	 digest);
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

  auth->ext_nid  = OBJ_txt2nid("authKeyId");
#ifndef NOGLOBUS
#ifdef HAVE_X509V3_EXT_METHOD_IT
  auth->it = NULL;
#endif
#else
#ifdef HAVE_X509V3_EXT_METHOD_IT_OPENSSL
  auth->it = NULL;
#endif
#endif
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

  avail->ext_nid  = OBJ_txt2nid("idcenoRevAvail");
#ifndef NOGLOBUS
#ifdef HAVE_X509V3_EXT_METHOD_IT
  avail->it = NULL;
#endif
#else
#ifdef HAVE_X509V3_EXT_METHOD_IT_OPENSSL
  avail->it = NULL;
#endif
#endif
  avail->ext_flags = 0;
  avail->ext_new  = (X509V3_EXT_NEW) ASN1_NULL_new;
  avail->ext_free = (X509V3_EXT_FREE)ASN1_NULL_free;
  avail->d2i      = (X509V3_EXT_D2I) d2i_ASN1_NULL;
  avail->i2d      = (X509V3_EXT_I2D) i2d_ASN1_NULL;
  avail->i2s      = (X509V3_EXT_I2S) null_i2s;
  avail->s2i      = (X509V3_EXT_S2I) null_s2i;
  avail->v2i      = (X509V3_EXT_V2I) NULL;
  avail->r2i      = (X509V3_EXT_R2I) NULL;
  avail->i2v      = (X509V3_EXT_I2V) NULL;
  avail->i2r      = (X509V3_EXT_I2R) NULL;

  targets->ext_nid  = OBJ_txt2nid("idceTargets");
#ifndef NOGLOBUS
#ifdef HAVE_X509V3_EXT_METHOD_IT
  targets->it = NULL;
#endif
#else
#ifdef HAVE_X509V3_EXT_METHOD_IT_OPENSSL
  targets->it = NULL;
#endif
#endif
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

  acseq->ext_nid  = OBJ_txt2nid("acseq");
#ifndef NOGLOBUS
#ifdef HAVE_X509V3_EXT_METHOD_IT
  acseq->it = NULL;
#endif
#else
#ifdef HAVE_X509V3_EXT_METHOD_IT_OPENSSL
  acseq->it = NULL;
#endif
#endif
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

  certseq->ext_nid  = OBJ_txt2nid("certseq");
#ifndef NOGLOBUS
#ifdef HAVE_X509V3_EXT_METHOD_IT
  certseq->it = NULL;
#endif
#else
#ifdef HAVE_X509V3_EXT_METHOD_IT_OPENSSL
  certseq->it = NULL;
#endif
#endif
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

  attribs->ext_nid  = OBJ_txt2nid("attributes");
#ifndef NOGLOBUS
#ifdef HAVE_X509V3_EXT_METHOD_IT
  attribs->it = NULL;
#endif
#else
#ifdef HAVE_X509V3_EXT_METHOD_IT_OPENSSL
  attribs->it = NULL;
#endif
#endif
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

  X509V3_EXT_add(avail);
  X509V3_EXT_add(targets);
  X509V3_EXT_add(auth);
  X509V3_EXT_add(acseq);
  X509V3_EXT_add(certseq);
  X509V3_EXT_add(attribs);

  return 1;
}
