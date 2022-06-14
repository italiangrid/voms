/*
 * Copyright 1999-2006 University of Chicago
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */


#ifndef HEADER_PROXYPOLICY_H
#define HEADER_PROXYPOLICY_H

/**
 * @file proxypolicy.h
 * @brief Proxy Policy
 * @author Sam Meder
 * @author Sam Lang
 */
/**
 * @defgroup proxypolicy ProxyPolicy
 * @ingroup globus_gsi_proxy_ssl_api
 *
 * The proxypolicy set of data structures
 * and functions provides an interface to generating
 * a PROXYPOLICY structure which is maintained as
 * a field in the PROXYCERTINFO structure,
 * and ultimately gets written to a DER encoded string.
 *
 * Further Information about proxy policies
 * is available in the <a href="http://www.ietf.org/rfc/rfc3820.txt">X.509 Proxy Certificate Profile</a> document.
 */

#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

#define ANY_LANGUAGE_OID         "1.3.6.1.5.5.7.21.0"
#define ANY_LANGUAGE_SN          "ANY_LANGUAGE"
#define ANY_LANGUAGE_LN          "Any Language"

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

/* Used for error handling */
#define ASN1_F_PROXYPOLICY_NEW          450
#define ASN1_F_D2I_PROXYPOLICY          451

  int PROXY_POLICY_set_policy_language(
      PROXY_POLICY *                       policy
    , ASN1_OBJECT *                       policy_language);
  
  int PROXY_POLICY_set_policy(
      PROXY_POLICY *                       proxypolicy
    , unsigned char *                     policy
    , int                                 length);

#if OPENSSL_VERSION_NUMBER < 0x30000000L
  PROXY_POLICY* PROXY_POLICY_dup(PROXY_POLICY* policy);
#else
  PROXY_POLICY* PROXY_POLICY_dup(const PROXY_POLICY* policy);
#endif
  
#ifdef __cplusplus
}
#endif

#endif /* HEADER_PROXYPOLICY_H */
