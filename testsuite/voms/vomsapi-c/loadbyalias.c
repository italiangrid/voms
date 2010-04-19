/*
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
 */
#include "voms_apic.h"
#include <stdlib.h>
#include <stdio.h>

int main(int argc, char *argv[]) {
  struct vomsdata *vd = VOMS_Init(NULL, NULL);
  int error = 0;

  if (vd) {

    struct contactdata **vomses = VOMS_FindByAlias(vd, "voms1", NULL, NULL, &error);

    if (vomses) {
      int total = 0;
      int count = 0;

      
      /* now we have parsed and verified the data */
      while (vomses[total++])
        ;
      
      total --;

      for (count = 0; count < total; count ++)
        printf("\"%s\" \"%s\" \"%s\" \"%s\" \"%ld\" \"%d\"\n", 
                vomses[count]->nick, vomses[count]->host,
                vomses[count]->contact, vomses[count]->vo, vomses[count]->port,
                vomses[count]->version);


      VOMS_DeleteContacts(vomses);

      exit(0);
    } else {
      fprintf(stderr, "Error Message1: %s\n", VOMS_ErrorMessage(vd, error, NULL, 0));
      exit (1);
    }
  } else {
    fprintf(stderr, "Error Message1: %s\n", VOMS_ErrorMessage(vd, error, NULL, 0));
    exit (1);
  }
}
