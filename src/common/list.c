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

#include <stdlib.h>
#include <string.h>

char **listadd(char **vect, char *data)
{
  int i = 0;
  char **newvect;

  if (!data)
    return vect;

  if (vect)
    while (vect[i++]) ;
  else
    i=1;

  if ((newvect = (char **)malloc((i+1)*sizeof(char *)))) {
    if (vect) {
      memcpy(newvect, vect, (sizeof(char*)*(i-1)));
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
