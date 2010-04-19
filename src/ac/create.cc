
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

extern "C" {
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/bn.h>

#include "newformat.h"
#include "write.h"
#include <stdlib.h>
#include "acerrors.h"
}

#include <cstring>

static void deallocate(char **v1, int s1, char **v2, int s2) 
{
  if (v1) {
    int i =0;
    while (i < s1)
      free(v1[i++]);
    free(v1);
  }

  if (v2) {
    int i =0;
    while (i < s2)
      free(v2[i++]);
    free(v2);
  }
}

int createac(X509 *issuerc, STACK_OF(X509) *issuerstack, X509 *holder, EVP_PKEY *pkey, BIGNUM *serial,
             std::vector<std::string> &fqan, std::vector<std::string> &targets, std::vector<std::string>& attributes,
             AC **ac, std::string vo, std::string uri, int valid, bool old,
             STACK_OF(X509_EXTENSION) *extensions)
{
  int size = fqan.size();
  char **array = NULL;
  char **array2 = NULL;

  // convert vector of strings to char**
  if ((array = (char **)calloc(size + 1, sizeof(char *))) && 
      (array2 = (char **)calloc(attributes.size() + 1, sizeof(char *)))) {
    int j = 0;
    for (std::vector<std::string>::iterator i = fqan.begin(); i != fqan.end(); i++) {
      array[j] = strdup((*i).c_str());
      if (!array[j]) {
        goto err;
      }
      j++;
    }

    j = 0;
    for (std::vector<std::string>::iterator i = attributes.begin(); i != attributes.end(); i++) {
      array2[j] = strdup((*i).c_str());
      if (!array2[j]) {
        goto err;
      }
      j++;
    }

    std::string complete;
    for (std::vector<std::string>::iterator i = targets.begin(); i != targets.end(); i++)
      if (i == targets.begin())
        complete = (*i);
      else
        complete += "," + (*i);
    
    int res = writeac(issuerc, issuerstack, holder, pkey, serial, array,
                      (complete.empty() ? NULL : const_cast<char *>(complete.c_str())), array2, 
                      ac, const_cast<char *>(vo.c_str()), const_cast<char *>(uri.c_str()), valid, (old ? 1 : 0), 
                      0, extensions);

    deallocate(array, size+1, array2, attributes.size() + 1);
    
    return res;
  }

 err:
  deallocate(array, size+1, array2, attributes.size() + 1);
  return false;
}
