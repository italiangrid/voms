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
#include <openssl/x509.h>
#include <openssl/evp.h>
#include <openssl/stack.h>

#include "internal.h"

namespace vomsspace {
internal::internal(): cert(NULL), key(NULL), chain(NULL)
{
}

internal::~internal()
{
  X509_free(cert);
  EVP_PKEY_free(key);
  sk_X509_pop_free(chain, X509_free);
}

}
