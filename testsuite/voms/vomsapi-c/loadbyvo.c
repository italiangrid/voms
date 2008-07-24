#include "voms_apic.h"
#include <stdlib.h>
#include <stdio.h>

int main(int argc, char *argv[]) {
  struct vomsdata *vd = VOMS_Init(NULL, NULL);
  int error = 0;

  if (vd) {

    struct contactdata **vomses = VOMS_FindByVO(vd, "voms1", NULL, NULL, &error);

    if (vomses) {
      int total = 0;
      int count = 0;

      
      /* now we have parsed and verified the data */
      while (vomses[total++])
        ;
      
      total --;

      for (count = 0; count < total; count ++)
        printf("\"%s\" \"%s\" \"%s\" \"%s\" \"%ld\" \"%ld\"\n", 
                vomses[count]->nick, vomses[count]->host,
                vomses[count]->contact, vomses[count]->vo, vomses[count]->port,
                vomses[count]->version);


      VOMS_DeleteContacts(vomses);

      exit(0);
    } else {
      fprintf(stderr, "Error Message1: %s\n", VOMS_ErrorMessage(vd, error, NULL, 0));
      exit (1);
    }
  } else {
    fprintf(stderr, "Error Message1: %s\n", VOMS_ErrorMessage(vd, error, NULL, 0));
    exit (1);
  }
}
