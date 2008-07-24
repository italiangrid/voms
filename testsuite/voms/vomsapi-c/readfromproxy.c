#include "voms_apic.h"
#include <stdio.h>

int main(int argc, char *argv[]) 
{
  struct vomsdata *vd = VOMS_Init(NULL, NULL);
  int error = 0;
  int i = 0;

  if (vd) {
    if (!VOMS_RetrieveFromProxy(RECURSE_CHAIN, vd, &error)) {
      fprintf(stderr, "Error is: %s\n", VOMS_ErrorMessage(vd, error, NULL, 0));
      exit(1);
    }
  }
  exit (0);
}
