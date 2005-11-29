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


static char *norep()
{
  char *buffer;

  buffer=malloc(1);
  if (buffer)
    *buffer='\0';
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

char *null_i2s(struct v3_ext_method *method, void *ext)
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
      list++;
    }
    if (pos)
      list = pos++;
  } while (pos);

  return a;

 err:
  AC_TARGETS_free(a);
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

  avail   = (X509V3_EXT_METHOD *)OPENSSL_malloc(sizeof(X509V3_EXT_METHOD));
  targets = (X509V3_EXT_METHOD *)OPENSSL_malloc(sizeof(X509V3_EXT_METHOD));
  auth    = (X509V3_EXT_METHOD *)OPENSSL_malloc(sizeof(X509V3_EXT_METHOD));
  acseq   = (X509V3_EXT_METHOD *)OPENSSL_malloc(sizeof(X509V3_EXT_METHOD));

  if (!avail || !targets || !auth || !acseq) {
    OPENSSL_free(avail);
    OPENSSL_free(targets);
    OPENSSL_free(auth);
    OPENSSL_free(acseq);
    return 0;
  }

  auth->ext_nid  = OBJ_txt2nid("authKeyId");
#ifdef HAVE_X509V3_EXT_METHOD_IT
  auth->it = NULL;
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
#ifdef HAVE_X509V3_EXT_METHOD_IT
  avail->it = NULL;
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
#ifdef HAVE_X509V3_EXT_METHOD_IT
  targets->it = NULL;
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
#ifdef HAVE_X509V3_EXT_METHOD_IT
  acseq->it = NULL;
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

  X509V3_EXT_add(avail);
  X509V3_EXT_add(targets);
  X509V3_EXT_add(auth);
  X509V3_EXT_add(acseq);

  return 1;
}
