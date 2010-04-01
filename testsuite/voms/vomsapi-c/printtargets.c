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

int main(int argc, char *argv[]) 
{
  struct vomsdata *vd = VOMS_Init(NULL, NULL);
  int error = 0;
  int i = 0;

  if (vd) {
    VOMS_SetVerificationType(VERIFY_NONE, vd,&error);

    if (VOMS_RetrieveFromProxy(RECURSE_CHAIN, vd, &error)) {
      struct voms *or = vd->data[0];
      char **targets = VOMS_GetTargetsList(or, vd, &error);

      if (targets) {
        int j = 0;
        while (targets[j])
          printf("Target: %s\n", targets[j++]);
      }
      VOMS_FreeTargetsList(targets);
      exit(0);
    }
    printf("Error: %s\n", VOMS_ErrorMessage(vd, error, NULL, 0));
  }
  exit (1);
}
