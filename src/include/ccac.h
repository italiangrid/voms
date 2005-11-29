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
#ifndef VOMS_CCAC_H
#define VOMS_CCAC_H

extern "C" {
#include <openssl/x509.h>
#include "newformat.h"
}

#include "voms_api.h"

enum ver_type {
  TYPE_COMPLETE,
  TYPE_NOTARGET
};


extern bool verifyac(X509 *, X509 *, AC *, voms &, ver_type type=TYPE_COMPLETE);
#endif

