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

#ifndef VOMS_API_CCVAL_H
#define VOMS_API_CCVAL_H

extern "C" {
#include <openssl/x509.h>
#include "newformat.h"
}

#include "voms_api.h"

extern bool verifyac(X509 *, X509 *, AC *, voms &, verify_type type);

#endif
