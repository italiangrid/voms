/*********************************************************************
 *
 * Authors: Vincenzo Ciaschini - Vincenzo.Ciaschini@cnaf.infn.it 
 *          Valerio Venturi    - Valerio.Venturi@cnaf.infn.it
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
#include <string.h>

#include <openssl/evp.h>
#include <openssl/asn1_mac.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/err.h>
#include <openssl/asn1.h>
#include <openssl/stack.h>
#include <openssl/safestack.h>
#include "newformat.h"
#include "acerrors.h"
#include "acstack.h"
#include "attributes.h"



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
