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
#ifndef VOMSAC_ACERRORS_H
#define VOMSAC_ACERRORS_H
#include "config.h"

#define ASN1_F_D2I_AC_ATTR          5000
#define AC_F_ATTR_New               5001
#define ASN1_F_D2I_AC_ROLE          5002
#define AC_F_ROLE_New               5003
#define ASN1_F_D2I_AC_IETFATTR      5004
#define AC_F_IETFATTR_New           5005
#define ASN1_F_D2I_AC_IETFATTRVAL   5006
#define ASN1_F_D2I_AC_DIGEST        5007
#define AC_F_DIGEST_New             5008
#define ASN1_F_D2I_AC_IS            5009
#define AC_F_AC_IS_New              5010
#define ASN1_F_D2I_AC_FORM          5011
#define AC_F_AC_FORM_New            5012
#define ASN1_F_D2I_AC_ACI           5013
#define ASN1_F_AC_ACI_New           5014
#define ASN1_F_D2I_AC_HOLDER        5015
#define ASN1_F_AC_HOLDER_New        5016
#define ASN1_F_AC_VAL_New           5017
#define AC_F_AC_INFO_NEW            5018
#define AC_F_D2I_AC                 5019
#define AC_F_AC_New                 5020
#define ASN1_F_I2D_AC_IETFATTRVAL   5021
#define AC_F_D2I_AC_DIGEST          5022
#define AC_F_AC_DIGEST_New          5023
#define AC_F_D2I_AC_IS              5024
#define AC_ERR_UNSET                5025
#define AC_ERR_SET                  5026
#define AC_ERR_SIGNATURE            5027
#define AC_ERR_VERSION              5028
#define AC_ERR_HOLDER_SERIAL        5029
#define AC_ERR_HOLDER               5030
#define AC_ERR_UID_MISMATCH         5031
#define AC_ERR_ISSUER_NAME          5032
#define AC_ERR_SERIAL               5033
#define AC_ERR_DATES                5034
#define AC_ERR_ATTRIBS              5035
#define AC_F_AC_TARGET_New          5036
#define ASN1_F_D2I_AC_TARGET        5037
#define AC_F_AC_TARGETS_New         5036
#define ASN1_F_D2I_AC_TARGETS       5037
#define ASN1_F_D2I_AC_SEQ           5038
#define AC_F_AC_SEQ_new             5039
#define AC_ERR_ATTRIB_URI           5040
#define AC_ERR_ATTRIB_FQAN          5041
#define AC_ERR_EXTS_ABSENT          5042
#define AC_ERR_MEMORY               5043
#define AC_ERR_EXT_CRIT             5044
#define AC_ERR_EXT_TARGET           5045
#define AC_ERR_EXT_KEY              5046
#define AC_ERR_UNKNOWN              5047

#define AC_ERR_PARAMETERS           5048
#define X509_ERR_ISSUER_NAME        5049
#define X509_ERR_HOLDER_NAME        5050
#define AC_ERR_NO_EXTENSION         5051

#define ASN1_F_D2I_AC_CERTS         5052
#define AC_F_X509_New               5053

#define AC_F_D2I_AC_ATTRIBUTE       5054
#define AC_F_ATTRIBUTE_New          5055
#define ASN1_F_D2I_AC_ATT_HOLDER    5056
#define AC_F_AC_ATT_HOLDER_New      5057
#define ASN1_F_D2I_AC_FULL_ATTRIBUTES 5058
#define AC_F_AC_FULL_ATTRIBUTES_New 5059
#define ASN1_F_D2I_AC_ATTRIBUTEVAL  5060
#define ASN1_F_I2D_AC_ATTRIBUTEVAL  5061
#define AC_F_AC_ATTRIBUTEVAL_New    5062
#define AC_ERR_ATTRIB               5063
#endif
