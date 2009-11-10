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

#include <stdlib.h>
#include <string.h>

char **listadd(char **vect, char *data, int size)
{
  int i = 0;
  char **newvect;

  if (!data || (size <= 0))
    return NULL;

  if (vect)
    while (vect[i++]) ;
  else
    i=1;

  if ((newvect = (char **)malloc((i+1)*size))) {
    if (vect) {
      memcpy(newvect, vect, (size*(i-1)));
      newvect[i-1] = data;
      newvect[i] = NULL;
      free(vect);
    }
    else {
      newvect[0] = data;
      newvect[1] = NULL;
    }
    return newvect;
  }
  return NULL;
}

void listfree(char **vect, void (*f)(void *))
{
  char **tmp = vect;

  if (tmp) {
    int i = 0;
    while (tmp[i])
      f(tmp[i++]);
    free(vect);
  }
}
