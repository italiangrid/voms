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
#ifndef VOMS_CCWRITE_H
#define VOMS_CCWRITE_H

extern "C" {
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/bn.h>

#include "newformat.h"
}

#include <vector>
#include <string>

extern int createac(X509 *, X509 *, EVP_PKEY *, BIGNUM *,
		     std::vector<std::string> &, std::vector<std::string> &, 
		     AC **, std::string, std::string, int valid, bool old);
#endif
