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
      struct voms **vomsarray = vd->data;
      while (vomsarray[total++])
        ;
       
      total --;

      if (argc == 2 && !strcmp(argv[1], "total"))
        printf("total: %d\n", total);

      if (argc == 1 || !strcmp(argv[1], "voname1"))
        printf("voname1: %s\n", vomsarray[0]->voname);

      if (argc == 1 || !strcmp(argv[1], "user1"))
        printf("user1: %s\n", vomsarray[0]->user);

      if (argc == 1 || !strcmp(argv[1], "userca1"))
        printf("userca1: %s\n", vomsarray[0]->userca);

      if (argc == 1 || !strcmp(argv[1], "server1"))
        printf("server1: %s\n", vomsarray[0]->server);

      if (argc == 1 || !strcmp(argv[1], "serverca1"))
        printf("serverca1: %s\n", vomsarray[0]->serverca);

      if (argc == 1 || !strcmp(argv[1], "uri1"))
        printf("uri1: %s\n", vomsarray[0]->uri);

      if (argc == 1 || !strcmp(argv[1], "begdate1"))
        printf("begdate1: %s\n", vomsarray[0]->date1);

      if (argc == 1 || !strcmp(argv[1], "enddate1"))
        printf("enddate1: %s\n", vomsarray[0]->date2);

      if (argc == 1 || !strcmp(argv[1], "fqan1")) {
        int index = 0;
        while (vomsarray[0]->fqan[index]) 
          printf("fqan1: %s\n", vomsarray[0]->fqan[index++]);
      }

      if (argc == 1 || !strcmp(argv[1], "version1"))
        printf("version1: %ld\n", vomsarray[0]->version);

      


      if ((argc == 1 || !strcmp(argv[1], "voname2")) && total == 2)
        printf("voname2: %s\n", vomsarray[1]->voname);

      if ((argc == 1 || !strcmp(argv[1], "user2")) && total == 2)
        printf("user2: %s\n", vomsarray[1]->user);

      if ((argc == 1 || !strcmp(argv[1], "userca2"))  && total == 2)
        printf("userca2: %s\n", vomsarray[1]->userca);

      if ((argc == 1 || !strcmp(argv[1], "server2")) && total == 2)
        printf("server2: %s\n", vomsarray[1]->server);

      if ((argc == 1 || !strcmp(argv[1], "serverca2")) && total == 2)
        printf("serverca2: %s\n", vomsarray[1]->serverca);

      if ((argc == 1 || !strcmp(argv[1], "uri2")) && total == 2)
        printf("uri2: %s\n", vomsarray[1]->uri);

      if ((argc == 1 || !strcmp(argv[1], "begdate2")) && total == 2)
        printf("begdate2: %s\n", vomsarray[1]->date1);

      if ((argc == 1 || !strcmp(argv[1], "enddate2")) && total == 2)
        printf("enddate2: %s\n", vomsarray[1]->date2);

      if ((argc == 1 || !strcmp(argv[1], "fqan2")) && total == 2) {
        int index = 0;
        while (vomsarray[1]->fqan[index]) 
          printf("fqan2: %s\n", vomsarray[1]->fqan[index++]);
      }

      if ((argc == 1 || !strcmp(argv[1], "version2")) && total == 2)
        printf("version2: %ld\n", vomsarray[1]->version);

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
