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

#include <string.h>
#include <stdlib.h>

#include "doio.h"

static char *change(const char *str, char *from, char *to)
{
  char *copy = strdup(str);

  if (!copy)
    return NULL;

  char *pos  = strstr(copy, from);
  char *tmp  = NULL;

  while (pos) {
    *pos = '\0';
    tmp = snprintf_wrap("%s%s%s", copy, to, pos + strlen(from));
    if (tmp) {
      free(copy);
      copy = tmp;
    }
    pos = strstr(copy + strlen(to), from);
  }

  return copy;
}

char *normalize(const char *str)
{
  char *tmp = NULL;
  char *tmp2 = NULL;

  tmp  = change(str, "/USERID=", "/UID=");
  tmp2 = change(tmp, "/emailAddress=", "/Email=");
  free(tmp);
  tmp  = change(tmp2, "/E=", "/Email=");
  free(tmp2);
  return tmp;
}

#if 0
int main(int argc, char *argv)
{
  char *str1="/prova/Email=frge/CN=op";
  char *str2="/prova/E=boh/emailAddress=mah/E=op/CN=fr";
  char *str3="/USERID=56/mah";

  char *n1 = normalize(str1);
  char *n2 = normalize(str2);
  char *n3 = normalize(str3);

  printf("%s -> %s\n", str1, n1);
  free(n1);
  printf("%s -> %s\n", str2, n2);
  free(n2);
  printf("%s -> %s\n", str3, n3);
  free(n3);

  exit(0);
}

#endif
