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

typedef struct myPROXYPOLICY_st {

    ASN1_OBJECT *                       policy_language;
    ASN1_OCTET_STRING *                 policy;

} myPROXYPOLICY;

typedef struct myPROXYCERTINFO_st {
 
  ASN1_INTEGER * path_length;
  myPROXYPOLICY * proxypolicy;
  int version;
} myPROXYCERTINFO;


/* myPROXYPOLICY function */

/* allocating and free memory */
myPROXYPOLICY * myPROXYPOLICY_new();
void myPROXYPOLICY_free(myPROXYPOLICY * proxypolicy);

/* duplicate */
myPROXYPOLICY * myPROXYPOLICY_dup(myPROXYPOLICY * policy);

/* set policy language */
int myPROXYPOLICY_set_policy_language(myPROXYPOLICY * policy, ASN1_OBJECT * policy_language);

/* get policy language */
ASN1_OBJECT * myPROXYPOLICY_get_policy_language(myPROXYPOLICY * policy);

/* set policy contents */
int myPROXYPOLICY_set_policy(myPROXYPOLICY * proxypolicy, unsigned char * policy, int length);

/* get policy contents */
unsigned char * myPROXYPOLICY_get_policy(myPROXYPOLICY * policy, int * length);

/* internal to der conversion */
int i2d_myPROXYPOLICY(myPROXYPOLICY * policy, unsigned char ** pp);

/* der to internal conversion */
myPROXYPOLICY * d2i_myPROXYPOLICY(myPROXYPOLICY ** policy, unsigned char ** pp, long length);

/*myPROXYCERTINFO function */

/* allocating and free memory */
myPROXYCERTINFO * myPROXYCERTINFO_new();
void myPROXYCERTINFO_free(myPROXYCERTINFO * proxycertinfo);

/* set path_length */
int myPROXYCERTINFO_set_path_length(myPROXYCERTINFO * proxycertinfo, long path_length);

/* get ptah length */
long myPROXYCERTINFO_get_path_length(myPROXYCERTINFO * proxycertinfo);

/* set proxypolicy */
int myPROXYCERTINFO_set_proxypolicy(myPROXYCERTINFO * proxycertinfo, myPROXYPOLICY * proxypolicy);

/* get proxypolicy */
myPROXYPOLICY * myPROXYCERTINFO_get_proxypolicy(myPROXYCERTINFO * proxycertinfo);

/* internal to der conversion */
int i2d_myPROXYCERTINFO(myPROXYCERTINFO * proxycertinfo, unsigned char ** pp);

/* der to internal conversion */
myPROXYCERTINFO * d2i_myPROXYCERTINFO(myPROXYCERTINFO ** cert_info, unsigned char ** a, long length);

int myPROXYCERTINFO_set_version(myPROXYCERTINFO *cert_info, int version);
#endif
