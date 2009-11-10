/*********************************************************************
 *
 * Authors: Vincenzo Ciaschini - Vincenzo.Ciaschini@cnaf.infn.it 
 *
 * Copyright (c) 2002-2009 INFN-CNAF on behalf of the EU DataGrid
 * and EGEE I, II and III
 * For license conditions see LICENSE file or
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 *
 * Parts of this code may be based upon or even include verbatim pieces,
 * originally written by other people, in which case the original header
 * follows.
 *
 *********************************************************************/
#include "config.h"

#include <openssl/err.h>

#include "acerrors.h"
#ifndef NO_ERR
static ERR_STRING_DATA AC_str_functs[] = {
  {ERR_PACK(0, ASN1_F_D2I_AC_ATTR, 0), "d2i_AC_ATTR"},
  {ERR_PACK(0, AC_F_ATTR_New, 0), "AC_ATTR_new"},
  {ERR_PACK(0, ASN1_F_D2I_AC_ROLE, 0), "d2i_AC_ROLE"},
  {ERR_PACK(0, AC_F_ROLE_New, 0), "AC_ROLE_new"},
  {ERR_PACK(0, ASN1_F_D2I_AC_IETFATTR, 0), "d2i_AC_IETFATTR"},
  {ERR_PACK(0, AC_F_IETFATTR_New, 0), "AC_IETFATTR_new"},
  {ERR_PACK(0, ASN1_F_D2I_AC_IETFATTRVAL, 0), "d2i_AC_IETFATTRVAL"},
  {ERR_PACK(0, ASN1_F_D2I_AC_DIGEST, 0), "d2i_AC_DIGEST"},
  {ERR_PACK(0, AC_F_DIGEST_New, 0), "AC_DIGEST_new"},
  {ERR_PACK(0, ASN1_F_D2I_AC_IS, 0), "d2i_AC_IS"},
  {ERR_PACK(0, AC_F_AC_IS_New, 0), "AC_IS_new"},
  {ERR_PACK(0, ASN1_F_D2I_AC_FORM, 0), "d2i_AC_FORM"},
  {ERR_PACK(0, AC_F_AC_FORM_New, 0), "AC_FORM_new"},
  {ERR_PACK(0, ASN1_F_D2I_AC_ACI, 0), "d2i_AC_ACI"},
  {ERR_PACK(0, ASN1_F_AC_ACI_New, 0), "AC_ACI_new"},
  {ERR_PACK(0, ASN1_F_D2I_AC_HOLDER, 0), "d2i_AC_HOLDER"},
  {ERR_PACK(0, ASN1_F_AC_HOLDER_New, 0), "AC_HOLDER_new"},
  {ERR_PACK(0, ASN1_F_D2I_AC_ATTR, 0), "d2i_AC_ATTR"},
  {ERR_PACK(0, AC_F_AC_INFO_NEW, 0), "AC_INFO_new"},
  {ERR_PACK(0, AC_F_D2I_AC, 0), "d2i_AC"},
  {ERR_PACK(0, AC_F_AC_New, 0), "AC_new"},
  {ERR_PACK(0, ASN1_F_I2D_AC_IETFATTRVAL, 0), "i2d_AC_IETFATTRVAL"},
  {ERR_PACK(0, AC_F_D2I_AC_DIGEST, 0), "d2i_AC_DIGEST"},
  {ERR_PACK(0, AC_F_AC_DIGEST_New, 0), "AC_DIGEST_new"},
  {ERR_PACK(0, AC_F_D2I_AC_IS, 0), "d2i_AC_IS"},
  {ERR_PACK(0, AC_ERR_UNSET, 0), "Required value unset"},
  {ERR_PACK(0, AC_ERR_SET, 0), "Value erroneously set"},
  {ERR_PACK(0, AC_ERR_SIGNATURE, 0), "Signature wrong"},
  {ERR_PACK(0, AC_ERR_VERSION, 0), "Version number wrong"},
  {ERR_PACK(0, AC_ERR_HOLDER_SERIAL, 0), "Holder serial number wrong"},
  {ERR_PACK(0, AC_ERR_HOLDER, 0), "Holder name wrong"},
  {ERR_PACK(0, AC_ERR_UID_MISMATCH, 0), "IssuerUID mismatch"},
  {ERR_PACK(0, AC_ERR_ISSUER_NAME, 0), "Issuer name wrong"},
  {ERR_PACK(0, AC_ERR_SERIAL, 0), "Serial number wrong"},
  {ERR_PACK(0, AC_ERR_DATES, 0), "Dates mismatch"},
  {ERR_PACK(0, AC_ERR_ATTRIBS, 0), "Attributes not present"},
  {ERR_PACK(0, AC_F_AC_TARGET_New, 0), "AC_TARGET_new"},
  {ERR_PACK(0, ASN1_F_D2I_AC_TARGET, 0), "d2i_AC_TARGET"},
  {ERR_PACK(0, AC_F_AC_TARGETS_New, 0), "AC_TARGETS_new"},
  {ERR_PACK(0, ASN1_F_D2I_AC_TARGETS, 0), "d2i_AC_TARGETS"},
  {ERR_PACK(0, ASN1_F_D2I_AC_SEQ, 0), "d2i_AC_SEQ"},
  {ERR_PACK(0, AC_F_AC_SEQ_new, 0), "AC_SEQ_new"},
  {ERR_PACK(0, AC_ERR_ATTRIBS, 0), "AC_FULL_ATTRIBUTES"},
  {0, NULL}};
#endif

#define ERR_LIB_AC 129

void ERR_load_AC_strings(void)
{
  static int init = 1;

  if (init) {
    init = 0;
#ifndef NO_ERR
    ERR_load_strings(ERR_LIB_AC, AC_str_functs);
#endif
  }
}
