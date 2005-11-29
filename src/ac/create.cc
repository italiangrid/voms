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

int createac(X509 *issuerc, X509 *holder, EVP_PKEY *pkey, BIGNUM *s,
	      std::vector<std::string> &c, std::vector<std::string> &t, 
	      AC **ac, std::string vo, std::string uri, int valid, bool old)
{
  int size = c.size();
  char **array = NULL;
  bool error = false;
  
  if ((array = (char **)malloc(sizeof(char *)*(size+1)))) {
    int j = 0;
    for (std::vector<std::string>::iterator i = c.begin(); i != c.end(); i++) {
      array[j]=strdup((*i).c_str());
      if (!array[j]) {
        error = true;
        break;
      }
      j++;
    }
    if (error) {
      for (int i=0; i < j; i++)
        free(array[j]);
      free(array);
      return false;
    }
    array[j]=NULL;

    std::string complete;

    for (std::vector<std::string>::iterator i = t.begin(); i != t.end(); i++)
      if (i == t.begin())
        complete = (*i);
      else
        complete += "," + (*i);

    int res = writeac(issuerc, holder, pkey, s, array, 
		      (complete.empty() ? NULL :
		       const_cast<char *>(complete.c_str())),
		      ac, const_cast<char *>(vo.c_str()), 
		      const_cast<char *>(uri.c_str()), valid, (old ? 1 : 0));

    for (int i = 0; i < size; i++)
      free(array[i]);
    free(array);
    return res;
  }
  return AC_ERR_MEMORY;
}
