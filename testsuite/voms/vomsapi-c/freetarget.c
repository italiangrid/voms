#include "voms_apic.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char *argv[]) {
  struct vomsdata *vd = VOMS_Init(NULL, NULL);
  int error = 0;

  char * command;
  char *host = NULL;

  command="G/voms1";

  if (argc == 1 || !strcmp(argv[1],""))
    host="localhost";
  else
    host = argv[1];

  if (vd) {

    struct contactdata **vomses = VOMS_FindByAlias(vd, "voms1", NULL, NULL, &error);

    if (vomses[0]) {
      VOMS_AddTarget(vd, host, &error);
      VOMS_FreeTargets(vd, &error);
      if (VOMS_Contact(vomses[0]->host, vomses[0]->port, vomses[0]->contact,
                       command, vd, &error)) {
        struct voms **vomsarray = vd->data;
        if (vomsarray && vomsarray[0]) {
          int index = 0;
	  
          char **targets = VOMS_GetTargetsList(vomsarray[0], vd, &error);

          if (targets[0] == NULL) {
            printf("No targets present.");
            exit(0);
          }
        }
      }
    }
  }

  fprintf(stderr, "Error Message1: %s\n", VOMS_ErrorMessage(vd, error, NULL, 0));
  exit (1);
}
