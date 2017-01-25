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
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/stack.h>
#include <openssl/safestack.h>

#include "acstack.h"

#ifndef VOMS_MAYBECONST
#if defined(D2I_OF)
#define VOMS_MAYBECONST const
#else
#define VOMS_MAYBECONST
#endif
#endif

typedef struct ACDIGEST {
  ASN1_ENUMERATED *type;
  ASN1_OBJECT     *oid;
  X509_ALGOR      *algor;
  ASN1_BIT_STRING *digest;
} AC_DIGEST;

typedef struct ACIS {
  GENERAL_NAMES *issuer;
  ASN1_INTEGER  *serial;
  ASN1_BIT_STRING *uid;
} AC_IS;

typedef struct ACFORM {
  GENERAL_NAMES *names;
  AC_IS         *is;
  AC_DIGEST     *digest;
} AC_FORM;

typedef struct ACACI {
  GENERAL_NAMES *names;
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

typedef ASN1_OCTET_STRING AC_IETFATTRVAL;

typedef struct ACIETFATTR {
  GENERAL_NAMES *names;
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
  STACK_OF(AC_IETFATTR) *ietfattr;
  STACK_OF(AC_FULL_ATTRIBUTES) *fullattributes;
} AC_ATTR;

typedef STACK_OF(AC_ATTR) AC_ATTRS;

typedef struct ACINFO {
  ASN1_INTEGER             *version;
  AC_HOLDER                *holder;
  GENERAL_NAMES            *form;
  X509_ALGOR               *alg;
  ASN1_INTEGER             *serial;
  AC_VAL                   *validity;
  AC_ATTRS                 *attrib;
  ASN1_BIT_STRING          *id;
  X509_EXTENSIONS          *exts;
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

DECLARE_ASN1_FUNCTIONS(AC_ATTRS)
DECLARE_ASN1_FUNCTIONS(AC_DIGEST)
DECLARE_ASN1_FUNCTIONS(AC_IS)
DECLARE_ASN1_FUNCTIONS(AC_FORM)
DECLARE_ASN1_FUNCTIONS(AC_ACI)
DECLARE_ASN1_FUNCTIONS(AC_HOLDER)
DECLARE_ASN1_FUNCTIONS(AC_VAL)
DECLARE_ASN1_FUNCTIONS(AC_IETFATTR)
DECLARE_ASN1_FUNCTIONS(AC_TARGET)
DECLARE_ASN1_FUNCTIONS(AC_TARGETS)
DECLARE_ASN1_FUNCTIONS(AC_ATTR)
DECLARE_ASN1_FUNCTIONS(AC_INFO)
DECLARE_ASN1_FUNCTIONS(AC)
DECLARE_ASN1_FUNCTIONS(AC_SEQ)
DECLARE_ASN1_FUNCTIONS(AC_CERTS)

DECLARE_ASN1_PRINT_FUNCTION(AC)

extern AC *AC_dup(AC *ac);

extern EVP_PKEY *EVP_PKEY_dup(EVP_PKEY *pkey);

extern int AC_verify(X509_ALGOR *algor1, ASN1_BIT_STRING *signature,char *data,EVP_PKEY *pkey);


#endif
