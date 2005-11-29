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
#ifndef VOMS_STREAMERS_H
#define VOMS_STREAMERS_H
#include <stdio.h>

extern void *FILEStreamerAdd(void *h, FILE *f, const char *name, int maxlog, int code, int reload);
extern int   FILEStreamerRem(void *h, void *f);
extern void *FileNameStreamerAdd(void *h, const char *name, int maxlog, int code, int reload);
extern int   FileNameStreamerRem(void *h, void *f);
extern void *SYSLOGStreamerAdd(void *h, int code);
extern int   SYSLOGStreamerRem(void *h, void *f);
#endif
