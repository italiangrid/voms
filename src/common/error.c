/*********************************************************************
 *
 * Authors: Vincenzo Ciaschini - Vincenzo.Ciaschini@cnaf.infn.it 
 *
 * Copyright (c) 2002-2009 INFN-CNAF on behalf of the EU DataGrid
 * and EGEE I, II and III
 * For license conditions see LICENSE file or
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 *
 * Parts of this code may be based upon or even include verbatim pieces,
 * originally written by other people, in which case the original header
 * follows.
 *
 *********************************************************************/
#include "config.h"

#include <stdlib.h>
#include <string.h>

#include "errortype.h"

void free_error(struct error *p)
{
  if (p)
    free(p->message);
  free(p);
}

struct error *alloc_error(int n, const char *e)
{
  char *m = strdup(e);
  struct error *er = (struct error *)malloc(sizeof(struct error));

  if (er && m) {
    er->message = m;
    er->num = n;
    return er;
  }

  free(m);
  free(er);
  return NULL;
}

