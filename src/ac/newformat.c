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
#include <string.h>

#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/err.h>
#include <openssl/asn1t.h>
#include <openssl/stack.h>
#include <openssl/safestack.h>
#include "newformat.h"
#include "acerrors.h"
#include "attributes.h"

#ifndef VOMS_MAYBECONST
#if defined(D2I_OF)
#define VOMS_MAYBECONST const
#else
#define VOMS_MAYBECONST
#endif
#endif

ASN1_SEQUENCE(AC_DIGEST) = {
  ASN1_SIMPLE(AC_DIGEST, type, ASN1_ENUMERATED),
  ASN1_OPT(AC_DIGEST, oid, ASN1_OBJECT),
  ASN1_SIMPLE(AC_DIGEST, algor,  X509_ALGOR),
  ASN1_SIMPLE(AC_DIGEST, digest, ASN1_BIT_STRING)
} ASN1_SEQUENCE_END(AC_DIGEST)

IMPLEMENT_ASN1_FUNCTIONS(AC_DIGEST)

ASN1_SEQUENCE(AC_IS) = {
  ASN1_SIMPLE(AC_IS, issuer, GENERAL_NAMES),
  ASN1_SIMPLE(AC_IS, serial, ASN1_INTEGER),
  ASN1_OPT(AC_IS, uid, ASN1_BIT_STRING)
} ASN1_SEQUENCE_END(AC_IS)

IMPLEMENT_ASN1_FUNCTIONS(AC_IS)

ASN1_SEQUENCE(AC_FORM) = {
  ASN1_OPT(AC_FORM, names, GENERAL_NAMES),
  ASN1_IMP_OPT(AC_FORM, is, AC_IS, 0),
  ASN1_IMP_OPT(AC_FORM, digest, AC_DIGEST, 1)
} ASN1_SEQUENCE_END(AC_FORM)

IMPLEMENT_ASN1_FUNCTIONS(AC_FORM)

ASN1_SEQUENCE(AC_ACI) = {
  ASN1_SEQUENCE_OF(AC_ACI, names, GENERAL_NAME),
  ASN1_SIMPLE(AC_ACI, form, AC_FORM)
} ASN1_SEQUENCE_END(AC_ACI)

IMPLEMENT_ASN1_FUNCTIONS(AC_ACI)

ASN1_SEQUENCE(AC_HOLDER) = {
  ASN1_IMP(AC_HOLDER, baseid, AC_IS, 0),
  ASN1_IMP_OPT(AC_HOLDER, name, GENERAL_NAMES, 1),
  ASN1_IMP_OPT(AC_HOLDER, digest, AC_DIGEST, 2)
} ASN1_SEQUENCE_END(AC_HOLDER)

IMPLEMENT_ASN1_FUNCTIONS(AC_HOLDER)

ASN1_SEQUENCE(AC_VAL) = {
  ASN1_SIMPLE(AC_VAL, notBefore, ASN1_GENERALIZEDTIME),
  ASN1_SIMPLE(AC_VAL, notAfter, ASN1_GENERALIZEDTIME),
} ASN1_SEQUENCE_END(AC_VAL)

IMPLEMENT_ASN1_FUNCTIONS(AC_VAL)

ASN1_SEQUENCE(AC_IETFATTR) = {
  ASN1_IMP_SEQUENCE_OF_OPT(AC_IETFATTR, names, GENERAL_NAME, 0),
  ASN1_SEQUENCE_OF(AC_IETFATTR, values, ASN1_OCTET_STRING)
} ASN1_SEQUENCE_END(AC_IETFATTR)

IMPLEMENT_ASN1_FUNCTIONS(AC_IETFATTR)

ASN1_SEQUENCE(AC_TARGET) = {
  ASN1_EXP(AC_TARGET, name, GENERAL_NAME, 0),
  ASN1_EXP(AC_TARGET, group, GENERAL_NAME, 1),
  ASN1_EXP(AC_TARGET, cert, AC_IS, 2),
} ASN1_SEQUENCE_END(AC_TARGET)

IMPLEMENT_ASN1_FUNCTIONS(AC_TARGET)

ASN1_SEQUENCE(AC_TARGETS) = {
  ASN1_SEQUENCE_OF(AC_TARGETS, targets, AC_TARGET)
} ASN1_SEQUENCE_END(AC_TARGETS)

IMPLEMENT_ASN1_FUNCTIONS(AC_TARGETS)

ASN1_SEQUENCE(AC_ATTRIBUTE) = {
  ASN1_SIMPLE(AC_ATTRIBUTE, name, ASN1_OCTET_STRING),
  ASN1_SIMPLE(AC_ATTRIBUTE, value, ASN1_OCTET_STRING),
  ASN1_SIMPLE(AC_ATTRIBUTE, qualifier, ASN1_OCTET_STRING)
} ASN1_SEQUENCE_END(AC_ATTRIBUTE)

IMPLEMENT_ASN1_FUNCTIONS(AC_ATTRIBUTE)

ASN1_SEQUENCE(AC_ATT_HOLDER) = {
  ASN1_SEQUENCE_OF(AC_ATT_HOLDER, grantor, GENERAL_NAME),
  ASN1_SEQUENCE_OF(AC_ATT_HOLDER, attributes, AC_ATTRIBUTE)
} ASN1_SEQUENCE_END(AC_ATT_HOLDER)

IMPLEMENT_ASN1_FUNCTIONS(AC_ATT_HOLDER)

ASN1_SEQUENCE(AC_FULL_ATTRIBUTES) = {
  ASN1_SEQUENCE_OF(AC_FULL_ATTRIBUTES, providers, AC_ATT_HOLDER)
} ASN1_SEQUENCE_END(AC_FULL_ATTRIBUTES)

IMPLEMENT_ASN1_FUNCTIONS(AC_FULL_ATTRIBUTES)

ASN1_SEQUENCE(AC_ATTR) = {
  ASN1_SIMPLE(AC_ATTR, type, ASN1_OBJECT),
  ASN1_SET_OF(AC_ATTR, ietfattr, AC_IETFATTR),
  ASN1_SEQUENCE_OF_OPT(AC_ATTR, fullattributes, AC_FULL_ATTRIBUTES)
} ASN1_SEQUENCE_END(AC_ATTR)

IMPLEMENT_ASN1_FUNCTIONS(AC_ATTR)

ASN1_ITEM_TEMPLATE(AC_ATTRS) =
        ASN1_EX_TEMPLATE_TYPE(ASN1_TFLG_SEQUENCE_OF, 0, AcAttrs, AC_ATTR)
ASN1_ITEM_TEMPLATE_END(AC_ATTRS)

IMPLEMENT_ASN1_FUNCTIONS(AC_ATTRS)

ASN1_SEQUENCE(AC_INFO) = {
  ASN1_SIMPLE(AC_INFO, version, ASN1_INTEGER), /* must be v2(1) */
  ASN1_SIMPLE(AC_INFO, holder, AC_HOLDER),
  ASN1_EXP(AC_INFO, form, GENERAL_NAMES, 0), /* in place of an implicitly-tagged
                                              * AC_FORM */
  ASN1_SIMPLE(AC_INFO, alg, X509_ALGOR),
  ASN1_SIMPLE(AC_INFO, serial, ASN1_INTEGER),
  ASN1_SIMPLE(AC_INFO, validity, AC_VAL),
  ASN1_SIMPLE(AC_INFO, attrib, AC_ATTRS),
  ASN1_OPT(AC_INFO, id, ASN1_BIT_STRING),
  ASN1_SIMPLE(AC_INFO, exts, X509_EXTENSIONS)
} ASN1_SEQUENCE_END(AC_INFO)

IMPLEMENT_ASN1_FUNCTIONS(AC_INFO)

ASN1_SEQUENCE(AC) = {
  ASN1_SIMPLE(AC, acinfo, AC_INFO),
  ASN1_SIMPLE(AC, sig_alg, X509_ALGOR),
  ASN1_SIMPLE(AC, signature, ASN1_BIT_STRING)
} ASN1_SEQUENCE_END(AC)

IMPLEMENT_ASN1_FUNCTIONS(AC)

#if OPENSSL_VERSION_NUMBER < 0x30000000L
AC * AC_dup(AC *x) { return ASN1_item_dup(ASN1_ITEM_rptr(AC), x); }
#else
AC * AC_dup(const AC *x) { return ASN1_item_dup(ASN1_ITEM_rptr(AC), x); }
#endif

ASN1_SEQUENCE(AC_SEQ) = {
  ASN1_SEQUENCE_OF(AC_SEQ, acs, AC)
} ASN1_SEQUENCE_END(AC_SEQ)

IMPLEMENT_ASN1_FUNCTIONS(AC_SEQ)

ASN1_SEQUENCE(AC_CERTS) = {
  ASN1_SEQUENCE_OF(AC_CERTS, stackcert, X509)
} ASN1_SEQUENCE_END(AC_CERTS)

IMPLEMENT_ASN1_FUNCTIONS(AC_CERTS)

EVP_PKEY *EVP_PKEY_dup(EVP_PKEY *pkey)
{
  return (EVP_PKEY *)ASN1_dup((i2d_of_void*)i2d_PrivateKey, (d2i_of_void*)d2i_AutoPrivateKey, pkey);
}

int AC_verify(X509_ALGOR *algor1, ASN1_BIT_STRING *signature,char *data, EVP_PKEY *pkey)
{
  return ASN1_verify((int (*)())i2d_AC_INFO, algor1, signature, data, pkey);
}
