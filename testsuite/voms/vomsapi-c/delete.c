#include "voms_apic.h"
#include <stdlib.h>

int main(int argc, char *argv[]) 
{
  struct vomsdata *vd = VOMS_Init(NULL, NULL);
  int error = 0;

  if (vd) {

    if (VOMS_RetrieveFromProxy(RECURSE_CHAIN, vd, &error)) {
      struct voms *or = VOMS_DefaultData(vd, &error);
      struct voms *cp = VOMS_Copy(vd->data[0], &error);

      VOMS_Delete(cp);
      exit(0);
    }
  }
  exit(1);
}
