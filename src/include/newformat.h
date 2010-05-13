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

#ifndef VOMS_NEW_FORMAT_H
#define VOMS_NEW_FORMAT_H

#include <openssl/evp.h>
#include <openssl/asn1.h>
#include <openssl/asn1_mac.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/stack.h>
#include <openssl/safestack.h>

#include "acstack.h"

typedef struct ACDIGEST {
  ASN1_ENUMERATED *type;
  ASN1_OBJECT     *oid;
  X509_ALGOR      *algor;
  ASN1_BIT_STRING *digest;
} AC_DIGEST;

typedef struct ACIS {
  STACK_OF(GENERAL_NAME) *issuer;
  ASN1_INTEGER  *serial;
  ASN1_BIT_STRING *uid;
} AC_IS;

typedef struct ACFORM {
  STACK_OF(GENERAL_NAME) *names;
  AC_IS         *is;
  AC_DIGEST     *digest;
} AC_FORM;

typedef struct ACACI {
  STACK_OF(GENERAL_NAME) *names;
  AC_FORM       *form;
} AC_ACI;

typedef struct ACHOLDER {
  AC_IS         *baseid;
  STACK_OF(GENERAL_NAMES) *name;
  AC_DIGEST     *digest;
} AC_HOLDER;

typedef struct ACVAL {
  ASN1_GENERALIZEDTIME *notBefore;
  ASN1_GENERALIZEDTIME *notAfter;
} AC_VAL;

typedef struct asn1_string_st AC_IETFATTRVAL;

typedef struct ACIETFATTR {
  STACK_OF(GENERAL_NAME)   *names;
  STACK_OF(AC_IETFATTRVAL) *values;
} AC_IETFATTR;

typedef struct ACTARGET {
  GENERAL_NAME *name;
  GENERAL_NAME *group;
  AC_IS        *cert;
} AC_TARGET;
 
typedef struct ACTARGETS {
  STACK_OF(AC_TARGET) *targets;
} AC_TARGETS;

typedef struct ACATTR {
  ASN1_OBJECT * type;
  int get_type;
  STACK_OF(AC_IETFATTR) *ietfattr;
  STACK_OF(AC_FULL_ATTRIBUTES) *fullattributes;
} AC_ATTR;
#define GET_TYPE_FQAN 1
#define GET_TYPE_ATTRIBUTES 2

typedef struct ACINFO {
  ASN1_INTEGER             *version;
  AC_HOLDER                *holder;
  AC_FORM                  *form;
  X509_ALGOR               *alg;
  ASN1_INTEGER             *serial;
  AC_VAL                   *validity;
  STACK_OF(AC_ATTR)        *attrib;
  ASN1_BIT_STRING          *id;
  STACK_OF(X509_EXTENSION) *exts;
} AC_INFO;

typedef struct ACC {
  AC_INFO         *acinfo;
  X509_ALGOR      *sig_alg;
  ASN1_BIT_STRING *signature;
} AC;

typedef struct ACSEQ {
  STACK_OF(AC) *acs;
} AC_SEQ;

typedef struct ACCERTS {
  STACK_OF(X509) *stackcert;
} AC_CERTS;

DECL_STACK(AC_TARGET)
DECL_STACK(AC_TARGETS)
DECL_STACK(AC_IETFATTR)
DECL_STACK(AC_IETFATTRVAL)
DECL_STACK(AC_ATTR)
DECL_STACK(AC)
DECL_STACK(AC_INFO)
DECL_STACK(AC_VAL)
DECL_STACK(AC_HOLDER)
DECL_STACK(AC_ACI)
DECL_STACK(AC_FORM)
DECL_STACK(AC_IS)
DECL_STACK(AC_DIGEST)
DECL_STACK(AC_CERTS)

extern int i2d_AC_ATTR(AC_ATTR *a, unsigned char **pp);
extern AC_ATTR *d2i_AC_ATTR(AC_ATTR **a, unsigned char **p, long length);
extern AC_ATTR *AC_ATTR_new();
extern void AC_ATTR_free(AC_ATTR *a);
extern int i2d_AC_IETFATTR(AC_IETFATTR *a, unsigned char **pp);
extern AC_IETFATTR *d2i_AC_IETFATTR(AC_IETFATTR **a, unsigned char **p, long length);
extern AC_IETFATTR *AC_IETFATTR_new();
extern void AC_IETFATTR_free (AC_IETFATTR *a);
extern int i2d_AC_IETFATTRVAL(AC_IETFATTRVAL *a, unsigned char **pp);
extern AC_IETFATTRVAL *d2i_AC_IETFATTRVAL(AC_IETFATTRVAL **a, unsigned char **pp, long length);
extern AC_IETFATTRVAL *AC_IETFATTRVAL_new();
extern void AC_IETFATTRVAL_free(AC_IETFATTRVAL *a);
extern int i2d_AC_DIGEST(AC_DIGEST *a, unsigned char **pp);
extern AC_DIGEST *d2i_AC_DIGEST(AC_DIGEST **a, unsigned char **pp, long length);;
extern AC_DIGEST *AC_DIGEST_new(void);
extern void AC_DIGEST_free(AC_DIGEST *a);
extern int i2d_AC_IS(AC_IS *a, unsigned char **pp);
extern AC_IS *d2i_AC_IS(AC_IS **a, unsigned char **pp, long length);
extern AC_IS *AC_IS_new(void);
extern void AC_IS_free(AC_IS *a);
extern int i2d_AC_FORM(AC_FORM *a, unsigned char **pp);
extern AC_FORM *d2i_AC_FORM(AC_FORM **a, unsigned char **pp, long length);
extern AC_FORM *AC_FORM_new(void);
extern void AC_FORM_free(AC_FORM *a);
extern int i2d_AC_ACI(AC_ACI *a, unsigned char **pp);
extern AC_ACI *d2i_AC_ACI(AC_ACI **a, unsigned char **pp, long length);
extern AC_ACI *AC_ACI_new(void);
extern void AC_ACI_free(AC_ACI *a);

extern int i2d_AC_HOLDER(AC_HOLDER *a, unsigned char **pp);
extern AC_HOLDER *d2i_AC_HOLDER(AC_HOLDER **a, unsigned char **pp, long length);
extern AC_HOLDER *AC_HOLDER_new(void);
extern void AC_HOLDER_free(AC_HOLDER *a);

/* new AC_VAL functions by Valerio */
extern int i2d_AC_VAL(AC_VAL *a, unsigned char **pp);
extern AC_VAL *d2i_AC_VAL(AC_VAL **a, unsigned char **pp, long length);
extern AC_VAL *AC_VAL_new(void);
extern void AC_VAL_free(AC_VAL *a);
/* end*/

extern int i2d_AC_INFO(AC_INFO *a, unsigned char **pp);
extern AC_INFO *d2i_AC_INFO(AC_INFO **a, unsigned char **p, long length);
extern AC_INFO *AC_INFO_new(void);
extern void AC_INFO_free(AC_INFO *a);
extern int i2d_AC(AC *a, unsigned char **pp) ;
extern AC *d2i_AC(AC **a, unsigned char **pp, long length);
extern AC *AC_new(void);
extern void AC_free(AC *a);
extern int i2d_AC_TARGETS(AC_TARGETS *a, unsigned char **pp) ;
extern AC_TARGETS *d2i_AC_TARGETS(AC_TARGETS **a, unsigned char **pp, long length);
extern AC_TARGETS *AC_TARGETS_new(void);
extern void AC_TARGETS_free(AC_TARGETS *a);
extern int i2d_AC_TARGET(AC_TARGET *a, unsigned char **pp) ;
extern AC_TARGET *d2i_AC_TARGET(AC_TARGET **a, unsigned char **pp, long length);
extern AC_TARGET *AC_TARGET_new(void);
extern void AC_TARGET_free(AC_TARGET *a);
extern int i2d_AC_SEQ(AC_SEQ *a, unsigned char **pp) ;
extern AC_SEQ *d2i_AC_SEQ(AC_SEQ **a, unsigned char **pp, long length);
extern AC_SEQ *AC_SEQ_new(void);
extern void AC_SEQ_free(AC_SEQ *a);

extern int i2d_AC_CERTS(AC_CERTS *a, unsigned char **pp) ;
extern AC_CERTS *d2i_AC_CERTS(AC_CERTS **a, unsigned char **pp, long length);
extern AC_CERTS *AC_CERTS_new(void);
extern void AC_CERTS_free(AC_CERTS *a);

extern AC *AC_dup(AC *ac);
extern EVP_PKEY *EVP_PKEY_dup(EVP_PKEY *pkey);

extern int AC_verify(X509_ALGOR *algor1, ASN1_BIT_STRING *signature,char *data,EVP_PKEY *pkey);

#endif
