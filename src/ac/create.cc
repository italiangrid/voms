
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

#include "config.h"

#include <vector>
#include <string>

#include "data.h"

extern "C" {
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/bn.h>

#include "newformat.h"
#include "write.h"
#include <stdlib.h>
#include "acerrors.h"
#include "listfunc.h"
}

#include <cstring>


int createac(X509 *issuerc, STACK_OF(X509) *issuerstack, X509 *holder, EVP_PKEY *pkey, BIGNUM *serial,
             std::vector<std::string> &fqan, std::vector<std::string> &targets, std::vector<std::string>& attributes,
             AC **ac, std::string vo, std::string uri, int valid, bool old,
             STACK_OF(X509_EXTENSION) *extensions)
{
  char **array = NULL;
  char **array2 = NULL;
  int res = 0;

  if ((array = vectoarray(fqan)) && (array2 = vectoarray(attributes))) {

    std::string complete;
    std::vector<std::string>::iterator const e = targets.end();
    for (std::vector<std::string>::iterator i = targets.begin(); i != e; ++i)
      if (i == targets.begin())
        complete = (*i);
      else
        complete += "," + (*i);
    
    res = writeac(issuerc, issuerstack, holder, pkey, serial, array,
                  (complete.empty() ? NULL : const_cast<char *>(complete.c_str())), array2, 
                  ac, const_cast<char *>(vo.c_str()), const_cast<char *>(uri.c_str()), valid, (old ? 1 : 0), 
                  0, extensions);

  }

  listfree(array, free);
  listfree(array2, free);

  return res;
}
