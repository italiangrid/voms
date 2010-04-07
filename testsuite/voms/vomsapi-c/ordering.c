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

  char * command;

  command="G/voms1";

  if (vd) {

    struct contactdata **vomses = VOMS_FindByAlias(vd, "voms1", NULL, NULL, &error);

    if (vomses[0]) {
      VOMS_Ordering("/voms1/group1,/voms1", vd, &error);
      if (VOMS_Contact(vomses[0]->host, vomses[0]->port, vomses[0]->contact,
                       command, vd, &error)) {
        struct voms *voms = VOMS_DefaultData(vd, &error);
        if (voms) {
          char **fqans = voms->fqan;
          while (*fqans) {
            printf("fqan: %s\n", *fqans++);
          }
          exit(0);
        }
      }
    }
  }

  fprintf(stderr, "Error Message1: %s\n", VOMS_ErrorMessage(vd, error, NULL, 0));
  exit (1);
}
