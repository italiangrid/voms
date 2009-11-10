#include "voms_apic.h"
#include <stdlib.h>
#include <stdio.h>

int main(int argc, char *argv[]) {
  struct vomsdata *vd = VOMS_Init(NULL, NULL);
  int error = 0;

  char *list = NULL;

  VOMS_AddTarget(vd, "prova.it", &error);
  VOMS_AddTarget(vd, "prova.com", &error);

  list = VOMS_ListTargets(vd, &error);

  if (list) {
	  printf("targets: %s\n", list);
    exit(0);
  }

  fprintf(stderr, "Error Message1: %s\n", VOMS_ErrorMessage(vd, error, NULL, 0));
  exit (1);
}
