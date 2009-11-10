#include "voms_apic.h"
#include <stdlib.h>

int main(int argc, char *argv[]) 
{
  struct vomsdata *vd = VOMS_Init(NULL, NULL);
  int error = 0;

  if (vd) {
    VOMS_Destroy(vd);
    exit(0);
  }
  exit(1);
}
