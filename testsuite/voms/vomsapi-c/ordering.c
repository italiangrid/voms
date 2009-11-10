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
