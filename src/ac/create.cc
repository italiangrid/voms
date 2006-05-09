
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

int createac(X509 *issuerc, STACK_OF(X509) *issuerstack, X509 *holder, EVP_PKEY *pkey, BIGNUM *serial,
             std::vector<std::string> &fqan, std::vector<std::string> &targets, std::vector<std::string>& attributes,
             AC **ac, std::string vo, std::string uri, int valid, bool old)
{
  int size = fqan.size();
  char **array = NULL;
  bool error = false;
  char **array2 = NULL;

  // convert vector of strings to char**
  if ((array = (char **)malloc(sizeof(char *)*(size+1))) && (array2 = (char **)malloc(sizeof(char *)*(attributes.size() +1))))
  {
    int j = 0;
    for (std::vector<std::string>::iterator i = fqan.begin(); i != fqan.end(); i++)
    {
      array[j] = strdup((*i).c_str());
      if (!array[j])
      {
        error = true;
        break;
      }
      j++;
    }
    if (error)
    {
      for (int i=0; i < j; i++)
        free(array[j]);
      free(array);
      return false;
    }
    array[j]=NULL;

    j = 0;
    for (std::vector<std::string>::iterator i = attributes.begin(); i != attributes.end(); i++)
    {
      array2[j] = strdup((*i).c_str());
      if (!array2[j])
      {
        error = true;
        break;
      }
      j++;
    }
    if (error)
    {
      for (int i=0; i < j; i++)
        free(array2[j]);
      free(array2);

      int i = 0;
      while (array[i])
        free(array[i++]);
      free(array);

      return false;
    }
    array2[j]=NULL;

    std::string complete;
    for (std::vector<std::string>::iterator i = targets.begin(); i != targets.end(); i++)
      if (i == targets.begin())
        complete = (*i);
      else
        complete += "," + (*i);
    
    int res = writeac(issuerc, issuerstack, holder, pkey, serial, array,
                      (complete.empty() ? NULL : const_cast<char *>(complete.c_str())), array2, 
                      ac, const_cast<char *>(vo.c_str()), const_cast<char *>(uri.c_str()), valid, (old ? 1 : 0));

    for (int i = 0; i < size; i++)
      free(array[i]);
    free(array);

    for (int i = 0; i < attributes.size(); i++)
      free(array2[i]);
    free(array2);
    
    return res;
  }

  return AC_ERR_MEMORY;
}
