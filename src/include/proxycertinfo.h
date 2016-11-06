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

#ifndef HEADER_PROXYCERTINFO_H
#define HEADER_PROXYCERTINFO_H

/**
 * @file proxycertinfo.h
 * @brief Proxy Certificate Info
 * @author Sam Meder
 * @author Sam Lang
 */
#include "proxypolicy.h"
#include <openssl/asn1.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @defgroup proxycertinfo ProxyCertInfo
 * @ingroup globus_gsi_proxy_ssl_api
 * 
 * The proxycertinfo.h file defines a method of
 * maintaining information about proxy certificates.
 */

#define PROXYCERTINFO_OLD_OID           "1.3.6.1.4.1.3536.1.222"
#define PROXYCERTINFO_OID               "1.3.6.1.5.5.7.1.14"
#define PROXYCERTINFO_SN                "PROXYCERTINFO"
#define PROXYCERTINFO_LN                "Proxy Certificate Info Extension"
#define PROXYCERTINFO_OLD_SN            "OLD_PROXYCERTINFO"
#define PROXYCERTINFO_OLD_LN                "Proxy Certificate Info Extension (old OID)"

/*
 * Used for error checking
 */
#define ASN1_F_PROXYCERTINFO_NEW                         430
#define ASN1_F_D2I_PROXYCERTINFO                         431


  X509V3_EXT_METHOD * PROXYCERTINFO_OLD_x509v3_ext_meth();

  void InitProxyCertInfoExtension(int full);

  int
  PROXY_CERT_INFO_EXTENSION_set_path_length(
      PROXY_CERT_INFO_EXTENSION* pci
    , long pl
  );
  
  PROXY_POLICY*
  PROXY_CERT_INFO_EXTENSION_get_policy(PROXY_CERT_INFO_EXTENSION const* pci);

  int
  PROXY_CERT_INFO_EXTENSION_set_policy(
      PROXY_CERT_INFO_EXTENSION* pci
    , PROXY_POLICY* policy
  );

  long
  PROXY_CERT_INFO_EXTENSION_get_path_length(PROXY_CERT_INFO_EXTENSION const* pci);

#ifdef __cplusplus
}
#endif

#endif /* HEADER_PROXYCERTINFO_H */
