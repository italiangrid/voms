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
