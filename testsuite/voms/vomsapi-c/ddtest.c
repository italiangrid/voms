#include "voms_apic.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char *argv[]) {
  struct vomsdata *vd = VOMS_Init(NULL, NULL);
  int error = 0;

  if (vd) {

    if (VOMS_RetrieveFromProxy(RECURSE_CHAIN, vd, &error)) {
      int total = 0;
      int count = 0;

      /* now we have parsed and verified the data */
      struct voms *voms = VOMS_DefaultData(vd, &error);

      if (argc == 2 && !strcmp(argv[1], "total"))
        printf("total: %d\n", 1);

      if (argc == 1 || !strcmp(argv[1], "voname1"))
        printf("voname1: %s\n", voms->voname);

      if (argc == 1 || !strcmp(argv[1], "user1"))
        printf("user1: %s\n", voms->user);

      if (argc == 1 || !strcmp(argv[1], "userca1"))
        printf("userca1: %s\n", voms->userca);

      if (argc == 1 || !strcmp(argv[1], "server1"))
        printf("server1: %s\n", voms->server);

      if (argc == 1 || !strcmp(argv[1], "serverca1"))
        printf("serverca1: %s\n", voms->serverca);

      if (argc == 1 || !strcmp(argv[1], "uri1"))
        printf("uri1: %s\n", voms->uri);

      if (argc == 1 || !strcmp(argv[1], "begdate1"))
        printf("begdate1: %s\n", voms->date1);

      if (argc == 1 || !strcmp(argv[1], "enddate1"))
        printf("enddate1: %s\n", voms->date2);

      if (argc == 1 || !strcmp(argv[1], "fqan1")) {
        int index = 0;
        while (voms->fqan[index]) 
          printf("fqan1: %s\n", voms->fqan[index++]);
      }

      if (argc == 1 || !strcmp(argv[1], "version1"))
        printf("version1: %ld\n", voms->version);

      exit (0);
    }
    else {
      fprintf(stderr, "Error Message2: %s\n", VOMS_ErrorMessage(vd, error, NULL, 0));
      exit (1);
    }
  }
  else {
    fprintf(stderr, "Error Message1: %s\n", VOMS_ErrorMessage(vd, error, NULL, 0));
    exit (1);
  }
}
