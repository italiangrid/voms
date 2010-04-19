/*********************************************************************
 *
 * Authors: Vincenzo Ciaschini - Vincenzo.Ciaschini@cnaf.infn.it 
 *
 * Copyright (c) Members of the EGEE Collaboration. 2004-2010.
 * See http://www.eu-egee.org/partners/ for details on the copyright holders.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
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
                    AC **, std::string, std::string, int valid, bool old,
                    STACK_OF(X509_EXTENSION) *extensions);
#endif
