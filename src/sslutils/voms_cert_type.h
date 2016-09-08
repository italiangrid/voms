#ifndef VOMS_CERT_TYPE_H
#define VOMS_CERT_TYPE_H

#ifdef __cplusplus
extern "C" {
#endif

#include "openssl/x509.h"

/**
 * This is shamelessly inspired by the Globus toolkit cert utils library 
 * 
 * https://github.com/globus/globus-toolkit/blob/globus_6_branch/gsi/cert_utils/source/library/globus_gsi_cert_utils_constants.h
 **/

typedef enum {
	VOMS_SUCCESS  = 0,
	VOMS_ERROR = -1
} voms_result_t;
	
typedef enum {

	VOMS_CERT_TYPE_UNKNOWN = 0,
	VOMS_CERT_TYPE_EEC = (1 << 0),
	VOMS_CERT_TYPE_CA  = (1 << 1),
	VOMS_CERT_TYPE_GSI_2 = (1 << 2),
	VOMS_CERT_TYPE_GSI_3 = (1 << 3),
	VOMS_CERT_TYPE_RFC = (1 << 4),

	/** Supported certificate types mask **/
	VOMS_CERT_TYPE_SUPPORTED_MASK = ( 
			VOMS_CERT_TYPE_EEC | 
			VOMS_CERT_TYPE_CA | 
			VOMS_CERT_TYPE_GSI_2 |
			VOMS_CERT_TYPE_GSI_3 |
			VOMS_CERT_TYPE_RFC ),

	/** Proxy types */
	VOMS_CERT_TYPE_IMPERSONATION_PROXY = (1 << 5),
	VOMS_CERT_TYPE_LIMITED_PROXY = (1 << 6),
	VOMS_CERT_TYPE_RESTRICTED_PROXY = (1 << 7),
	VOMS_CERT_TYPE_INDEPENDENT_PROXY = (1 << 8),

	/** Proxy types mask **/
	VOMS_CERT_TYPE_PROXY_TYPE_MASK = (
			VOMS_CERT_TYPE_IMPERSONATION_PROXY |
			VOMS_CERT_TYPE_LIMITED_PROXY |
			VOMS_CERT_TYPE_RESTRICTED_PROXY |
			VOMS_CERT_TYPE_INDEPENDENT_PROXY),

	VOMS_CERT_TYPE_GSI_3_IMPERSONATION_PROXY = (
			VOMS_CERT_TYPE_GSI_3 |
			VOMS_CERT_TYPE_INDEPENDENT_PROXY),

	VOMS_CERT_TYPE_GSI_3_INDEPENDENT_PROXY =
		(VOMS_CERT_TYPE_GSI_3 |
		 VOMS_CERT_TYPE_INDEPENDENT_PROXY),

	/** A X.509 Proxy Certificate Profile (pre-RFC) compliant
	 *  limited proxy
	 */
	VOMS_CERT_TYPE_GSI_3_LIMITED_PROXY =
		(VOMS_CERT_TYPE_GSI_3 |
		 VOMS_CERT_TYPE_LIMITED_PROXY),

	/** A X.509 Proxy Certificate Profile (pre-RFC) compliant
	 *  restricted proxy
	 */
	VOMS_CERT_TYPE_GSI_3_RESTRICTED_PROXY =
		(VOMS_CERT_TYPE_GSI_3 |
		 VOMS_CERT_TYPE_RESTRICTED_PROXY),

	/** A legacy Globus impersonation proxy */
	VOMS_CERT_TYPE_GSI_2_PROXY =
		(VOMS_CERT_TYPE_GSI_2 |
		 VOMS_CERT_TYPE_IMPERSONATION_PROXY),

	/** A legacy Globus limited impersonation proxy */
	VOMS_CERT_TYPE_GSI_2_LIMITED_PROXY =
		(VOMS_CERT_TYPE_GSI_2 |
		 VOMS_CERT_TYPE_LIMITED_PROXY),

	/** A X.509 Proxy Certificate Profile RFC compliant impersonation proxy */
	VOMS_CERT_TYPE_RFC_IMPERSONATION_PROXY =
		(VOMS_CERT_TYPE_RFC |
		 VOMS_CERT_TYPE_IMPERSONATION_PROXY),

	/** A X.509 Proxy Certificate Profile RFC compliant independent proxy */
	VOMS_CERT_TYPE_RFC_INDEPENDENT_PROXY =
		(VOMS_CERT_TYPE_RFC | 
		 VOMS_CERT_TYPE_INDEPENDENT_PROXY),

	/** A X.509 Proxy Certificate Profile RFC compliant limited proxy */
	VOMS_CERT_TYPE_RFC_LIMITED_PROXY =
		(VOMS_CERT_TYPE_RFC | 
		 VOMS_CERT_TYPE_LIMITED_PROXY),

	/** A X.509 Proxy Certificate Profile RFC compliant restricted proxy */
	VOMS_CERT_TYPE_RFC_RESTRICTED_PROXY =
		(VOMS_CERT_TYPE_RFC | 
		 VOMS_CERT_TYPE_RESTRICTED_PROXY)
} voms_cert_type_t;


#define VOMS_IS_PROXY(cert_type) \
        ((cert_type & VOMS_CERT_TYPE_PROXY_TYPE_MASK) != 0)

#define VOMS_IS_RFC_PROXY(cert_type) \
        (((cert_type & VOMS_CERT_TYPE_PROXY_TYPE_MASK) != 0) && \
         ((cert_type & VOMS_CERT_TYPE_RFC) != 0))

#define VOMS_IS_GSI_3_PROXY(cert_type) \
        (((cert_type & VOMS_CERT_TYPE_PROXY_TYPE_MASK) != 0) && \
         ((cert_type & VOMS_CERT_TYPE_GSI_3) != 0))

#define VOMS_IS_GSI_2_PROXY(cert_type) \
        (((cert_type & VOMS_CERT_TYPE_PROXY_TYPE_MASK) != 0) && \
         ((cert_type & VOMS_CERT_TYPE_GSI_2) != 0))

#define VOMS_IS_INDEPENDENT_PROXY(cert_type) \
        ((cert_type & VOMS_CERT_TYPE_INDEPENDENT_PROXY) != 0)

#define VOMS_IS_RESTRICTED_PROXY(cert_type) \
        ((cert_type & VOMS_CERT_TYPE_RESTRICTED_PROXY) != 0)

#define VOMS_IS_LIMITED_PROXY(cert_type) \
        ((cert_type & VOMS_CERT_TYPE_LIMITED_PROXY) != 0)

#define VOMS_IS_IMPERSONATION_PROXY(cert_type) \
        ((cert_type & VOMS_CERT_TYPE_IMPERSONATION_PROXY) != 0)

voms_result_t 
voms_get_cert_type(X509* cert, voms_cert_type_t* cert_type);

#ifdef __cplusplus
}
#endif
#endif
