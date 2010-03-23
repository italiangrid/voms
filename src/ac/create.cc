
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

extern char *Encode(const char *, int, int *);
extern char *Decode(const char *, int, int *);

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
             AC **ac, std::string vo, std::string uri, int valid, bool old)
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
                      ac, const_cast<char *>(vo.c_str()), const_cast<char *>(uri.c_str()), valid, (old ? 1 : 0), 0);

    deallocate(array, size+1, array2, attributes.size() + 1);
    
    return res;
  }

 err:
  deallocate(array, size+1, array2, attributes.size() + 1);
  return false;
}
