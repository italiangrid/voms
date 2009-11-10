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
#include <openssl/stack.h>
#include <openssl/evp.h>

namespace vomsspace {
class internal {
 public:
  internal();
  ~internal();
  X509 *cert;
  EVP_PKEY *key;
  STACK_OF(X509) *chain;
};

};

