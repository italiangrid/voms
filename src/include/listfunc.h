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
#ifndef VOMS_LISTFUNC_H
#define VOMS_LISTFUNC_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdlib.h>

typedef void (*freefn)(void *);

extern char **listjoin(char **base, char **addon, int size);
extern char **listadd(char **vect, char *data, int size);
extern void   listfree(char **vect, freefn f);

#ifdef __cplusplus
}
#endif

#endif
