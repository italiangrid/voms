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
#ifndef VOMS_SIGN_H
#define VOMS_SIGN_H
#include <string>

#ifdef __cplusplus
extern "C" {
#endif

#include <openssl/pem.h>

#ifdef __cplusplus
}
#endif

extern bool sign(EVP_PKEY *pkey, const std::string source, std::string &result);
extern bool verify(EVP_PKEY *key, const std::string data, const std::string signature);
#endif /* ___SIGN_H */
