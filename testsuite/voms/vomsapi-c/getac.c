#include "voms_apic.h"
#include <stdlib.h>

int main(int argc, char *argv[]) 
{
  struct vomsdata *vd = VOMS_Init(NULL, NULL);
  int error;

  if (vd) {
    if (VOMS_RetrieveFromProxy(RECURSE_CHAIN, vd, &error)) {
      struct voms *or = VOMS_DefaultData(vd, &error);
      if (or) {
        struct AC *ac = VOMS_GetAC(or);
        if (ac) {
          AC_free(ac);
          exit(0);
        }
      }
    }
  }
  exit(1);
}
