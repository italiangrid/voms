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

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>

char *vsnprintf_wrap(const char *format, va_list v)
{
  va_list w;

  va_copy(w,v);;
  char *str = NULL;
  int plen = 0;

  plen = vsnprintf(str, 0, format, v);

  if (plen > 0) {
    str = (char *)malloc(plen+1);
    if (str) {
      (void)vsnprintf(str, plen+1, format, w);
      va_end(w);
    }
  }

  return str;
}

char *snprintf_wrap(const char *format, ...)
{
  va_list v;
  char *str = NULL;

  va_start(v, format);
  str = vsnprintf_wrap(format, v);
  va_end(v);

  return str;
}

int fileexists(const char *file) 
{
  FILE *f = fopen(file, "r");
  close(f);

  return f != NULL;
}

