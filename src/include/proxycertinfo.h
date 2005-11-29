/*********************************************************************
 *
 * Authors: Vincenzo Ciaschini - Vincenzo.Ciaschini@cnaf.infn.it 
 *          Valerio Venturi    - valerio.venturi@cnaf.infn.it
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
#ifndef VOMS_PROXYCERTINFO_H
#define VOMS_PROXYCERTINFO_H

#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <string.h>

/* predefined policy language */
#define IMPERSONATION_PROXY_OID         "1.3.6.1.5.5.7.21.1"
#define IMPERSONATION_PROXY_SN          "IMPERSONATION_PROXY"
#define IMPERSONATION_PROXY_LN          "GSI impersonation proxy"

#define INDEPENDENT_PROXY_OID           "1.3.6.1.5.5.7.21.2"
#define INDEPENDENT_PROXY_SN            "INDEPENDENT_PROXY"
#define INDEPENDENT_PROXY_LN            "GSI independent proxy"

/* generic policy language */
#define GLOBUS_GSI_PROXY_GENERIC_POLICY_OID "1.3.6.1.4.1.3536.1.1.1.8"

#define LIMITED_PROXY_OID               "1.3.6.1.4.1.3536.1.1.1.9"
#define LIMITED_PROXY_SN                "LIMITED_PROXY"
#define LIMITED_PROXY_LN                "GSI limited proxy"

/* error handling */
#define ASN1_F_PROXYPOLICY_NEW          450
#define ASN1_F_D2I_PROXYPOLICY          451
#define ASN1_F_PROXYCERTINFO_NEW        430
#define ASN1_F_D2I_PROXYCERTINFO        431

/* data structure */

typedef struct PROXYPOLICY_st {

    ASN1_OBJECT *                       policy_language;
    ASN1_OCTET_STRING *                 policy;

} PROXYPOLICY;

typedef struct PROXYCERTINFO_st {
 
  ASN1_INTEGER * path_length;
  PROXYPOLICY * proxypolicy;

} PROXYCERTINFO;


/* PROXYPOLICY function */

/* allocating and free memory */
PROXYPOLICY * PROXYPOLICY_new();
void PROXYPOLICY_free(PROXYPOLICY * proxypolicy);

/* duplicate */
PROXYPOLICY * PROXYPOLICY_dup(PROXYPOLICY * policy);

/* set policy language */
int PROXYPOLICY_set_policy_language(PROXYPOLICY * policy, ASN1_OBJECT * policy_language);

/* get policy language */
ASN1_OBJECT * PROXYPOLICY_get_policy_language(PROXYPOLICY * policy);

/* set policy contents */
int PROXYPOLICY_set_policy(PROXYPOLICY * proxypolicy, unsigned char * policy, int length);

/* get policy contents */
unsigned char * PROXYPOLICY_get_policy(PROXYPOLICY * policy, int * length);

/* internal to der conversion */
int i2d_PROXYPOLICY(PROXYPOLICY * policy, unsigned char ** pp);

/* der to internal conversion */
PROXYPOLICY * d2i_PROXYPOLICY(PROXYPOLICY ** policy, unsigned char ** pp, long length);

/*PROXYCERTINFO function */

/* allocating and free memory */
PROXYCERTINFO * PROXYCERTINFO_new();
void PROXYCERTINFO_free(PROXYCERTINFO * proxycertinfo);

/* set path_length */
int PROXYCERTINFO_set_path_length(PROXYCERTINFO * proxycertinfo, long path_length);

/* get ptah length */
long PROXYCERTINFO_get_path_length(PROXYCERTINFO * proxycertinfo);

/* set proxypolicy */
int PROXYCERTINFO_set_proxypolicy(PROXYCERTINFO * proxycertinfo, PROXYPOLICY * proxypolicy);

/* get proxypolicy */
PROXYPOLICY * PROXYCERTINFO_get_proxypolicy(PROXYCERTINFO * proxycertinfo);

/* internal to der conversion */
int i2d_PROXYCERTINFO(PROXYCERTINFO * proxycertinfo, unsigned char ** pp);

/* der to internal conversion */
PROXYCERTINFO * d2i_PROXYCERTINFO(PROXYCERTINFO ** cert_info, unsigned char ** a, long length);

#endif
