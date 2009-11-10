#include "voms_apic.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char *argv[]) {
  struct vomsdata *vd = VOMS_Init(NULL, NULL);
  int error = 0;

  char * command;

  if (argc == 1 || !strcmp(argv[1],"")) 
    command="G/voms1";
  else
    command = argv[1];

  if (vd) {

    struct contactdata **vomses = VOMS_FindByAlias(vd, "voms1", NULL, NULL, &error);

    if (vomses[0]) {
      if (VOMS_Contact(vomses[0]->host, vomses[0]->port, vomses[0]->contact,
                       command, vd, &error)) {
        struct voms **vomsarray = vd->data;
        if (vomsarray && vomsarray[0]) {
          int index = 0;

          printf("voname1: %s\n", vomsarray[0]->voname);
          printf("user1: %s\n", vomsarray[0]->user);
          printf("userca1: %s\n", vomsarray[0]->userca);
          printf("server1: %s\n", vomsarray[0]->server);
          printf("serverca1: %s\n", vomsarray[0]->serverca);
          printf("uri1: %s\n", vomsarray[0]->uri);
          printf("begdate1: %s\n", vomsarray[0]->date1);
          printf("enddate1: %s\n", vomsarray[0]->date2);

          while (vomsarray[0]->fqan[index]) 
            printf("fqan1: %s\n", vomsarray[0]->fqan[index++]);

          printf("version1: %d\n", vomsarray[0]->version);

          exit(0);
        }
      }
    }
  }

  fprintf(stderr, "Error Message1: %s\n", VOMS_ErrorMessage(vd, error, NULL, 0));
  exit (1);
}
