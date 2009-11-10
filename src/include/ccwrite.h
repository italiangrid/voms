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

extern int createac(X509 *, STACK_OF(X509) *, X509 *, EVP_PKEY *, BIGNUM *,
                    std::vector<std::string> &, std::vector<std::string> &, std::vector<std::string>& attributes, 
                    AC **, std::string, std::string, int valid, bool old);
#endif
