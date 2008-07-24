#include "voms_apic.h"
#include <stdio.h>

int main(int argc, char *argv[]) 
{
  struct vomsdata *vd = VOMS_Init(NULL, NULL);
  int error = 0;
  int i = 0;

  if (vd) {
    if (argc !=2) {
      fprintf(stderr, "File argument missing.\n");
      exit(1);
    }

    FILE *f = fopen(argv[1], "rb");
    if (f) {
      if (!VOMS_RetrieveFromFile(f,RECURSE_CHAIN, vd, &error)) {
        fclose(f);
        fprintf(stderr, "Error is: %s\n", VOMS_ErrorMessage(vd, error, NULL, 0));
        exit(1);
      }
      fclose(f);
      exit(0);
    }
  }
  exit(1);
}

