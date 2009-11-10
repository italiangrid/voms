#include "voms_apic.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

static void errorp(char *message)
{
  fprintf(stderr, message);
  exit(1);
}

static int mystrcmp(char *l, char *r)
{
  if (!l && !r)
    return 0;

  if ((!l && r) || (l && !r))
    return 1;

  return strcmp(l,r);
}

static int mystrcmplen(int n, char *l, char *r)
{
  if (!l && !r)
    return 0;

  if ((!l && r) || (l && !r))
    return 1;

  return memcmp(l,r,n);
}



int main(int argc, char *argv[]) 
{
  struct vomsdata *vd = VOMS_Init(NULL, NULL);
  int error = 0;
  int i = 0;

  if (vd) {

    if (VOMS_RetrieveFromProxy(RECURSE_CHAIN, vd, &error)) {
      struct voms *or = vd->data[0];
      struct voms *cp = VOMS_Copy(vd->data[0], &error);

      if (cp) {
        struct data **copystd = NULL;
        struct data **origstd = NULL;
        char **orfqan = NULL;
        char **cpfqan = NULL;
        int j = 0;
          
        if ((!cp && or) || (cp && !or))
          errorp("Extra AC somewhere");
          
        if (!cp && !or)
          exit(0);

        if (cp->siglen != or->siglen)
          errorp("siglen differs");

        if (mystrcmplen(cp->siglen, cp->signature, or->signature))
          errorp("signature differs");

        if (mystrcmp(cp->userca, or->userca))
          errorp("userca differs");

        if (mystrcmp(cp->user, or->user))
          errorp("user differs");

        if (mystrcmp(cp->server, or->server))
          errorp("server differs");

        if (mystrcmp(cp->serverca, or->serverca))
          errorp("serverca differs");

        if (mystrcmp(cp->voname, or->voname))
          errorp("voname differs");

        if (mystrcmp(cp->uri, or->uri))
          errorp("uri differs");

        if (mystrcmp(cp->date1, or->date1))
          errorp("date1 differs");

        if (mystrcmp(cp->date2, or->date2))
          errorp("date2 differs");

        if (cp->type != or->type)
          errorp("type differs");

        if ((or->std && !cp->std) || (!or->std && cp->std))
          errorp("Extra FQAN");

        origstd = or->std;
        copystd = cp->std;

        do {
          struct data *dcp = copystd[j];
          struct data *dor = origstd[j];

          if ((dcp && !dor) || (!dcp && dor))
            errorp("Extra FQAN");

          if (!dcp && !dor)
            break;

          if (mystrcmp(dcp->group, dor->group))
            errorp("Group differs");

          if (mystrcmp(dcp->role, dor->role))
            errorp("Role differs");

          if (mystrcmp(dcp->cap, dor->cap))
            errorp("Capability differs");
          j++;
        } while (1);

        if (cp->datalen != or->datalen)
          errorp("datalen differs:");

        if (mystrcmplen(cp->datalen, cp->custom, or->custom))
          errorp("custom differs");

        if (mystrcmp(cp->serial, or->serial))
          errorp("serial differs");

        orfqan = or->fqan;
        cpfqan = cp->fqan;
        j = 0;

        if ((!orfqan && cpfqan) || (orfqan && !cpfqan))
          errorp("FQAN differ");

        do {
          char *ofqan = orfqan[j];
          char *cfqan = cpfqan[j];

          if ((ofqan && !cfqan) || (!ofqan && cfqan))
            errorp("Extra FQAN");
          
          if (!ofqan && ! cfqan)
            break;

          if (mystrcmp(ofqan, cfqan))
            errorp("FQAN differs");
          j++;
        } while (1);

        /* Now do generic attributes. */
        {
          int onum = VOMS_GetAttributeSourcesNumber(or, vd, &error);
          int cnum = VOMS_GetAttributeSourcesNumber(cp, vd, &error);
          int k = 0;
          if (onum != cnum)
            errorp("Different GA number");

          if (onum == -1)
            errorp("Error in retrieving GA");
          
          if (onum) 
            for (k = 0; k < onum; k++) {
              int oh = VOMS_GetAttributeSourceHandle(or, k, vd, &error);
              int ch = VOMS_GetAttributeSourceHandle(cp, k, vd, &error);
              int on = 0;
              int cn = 0;
              char *ogrnt = NULL;
              char *cgrnt = NULL;
              int l = 0;

              if (oh == -1 || ch == -1)
                errorp("Error in retrieving GA");

              ogrnt = VOMS_GetAttributeGrantor(or, oh, vd, &error);
              cgrnt = VOMS_GetAttributeGrantor(cp, ch, vd, &error);

              if (mystrcmp(ogrnt, cgrnt))
                errorp("Difference in grantors");

              on = VOMS_GetAttributesNumber(or, oh, vd, &error);
              cn = VOMS_GetAttributesNumber(cp, ch, vd, &error);

              if (on != cn || on == -1)
                errorp("Error in retrieving GAs");

              for (l = 0; l < on; l++) {
                struct attribute oa;
                struct attribute ca;

                if (!VOMS_GetAttribute(or, oh, l, &oa, vd, &error) ||
                    !VOMS_GetAttribute(cp, ch, l, &ca, vd, &error))
                  errorp("Error in getting Attribute");

                if (mystrcmp(oa.name, ca.name))
                  errorp("Error in name");

                if (mystrcmp(oa.qualifier, ca.qualifier))
                  errorp("Error in qualifier");
                if (mystrcmp(oa.value, ca.value))
                  errorp("Error in value");
              }  
            }
        }
      }
      else
        errorp("Error in making copy");
      exit(0);
    }
    else {
      errorp("Cannot retrieve from proxy.");
    }
  }
  exit (1);
}
