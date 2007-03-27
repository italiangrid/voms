/*********************************************************************
 *
 * Authors: Vincenzo Ciaschini - Vincenzo.Ciaschini@cnaf.infn.it 
 *
 * Copyright (c) 2002, 2003 INFN-CNAF on behalf of the EU DataGrid.
 * For license conditions see LICENSE file or
 * http://www.edg.org/license.html
 *
 * Parts of this code may be based upon or even include verbatim pieces,
 * originally written by other people, in which case the original header
 * follows.
 *
 *********************************************************************/
#include "config.h"
#include "log.h"
#include "streamers.h"

#include <stdio.h>

#if 0
void *FileNameStreamerAdd(void *h, const char *name, int maxlog, int code, int reload)
{
  if (h && name) {
    FILE *f=fopen(name, "a+");
    if (f)
      return FILEStreamerAdd(h, f, name, maxlog, code, reload);
  }
  return NULL;
}

int FileNameStreamerRem(void *h, void *f)
{
  if (h && f) {
    int res = FILEStreamerRem(h,f);
    fclose((FILE *)f);
    return res;
  }
  return 0;
}

#endif
