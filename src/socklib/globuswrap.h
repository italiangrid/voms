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
#ifndef VOMS_GLOBUSWRAP_H
#define VOMS_GLOBUSWRAP_H
#include <globus_gss_assist.h>

extern int my_recv(OM_uint32 *, const gss_ctx_id_t, char **, size_t *, int *,
		   int (*)(void *, void **, size_t *), void *, void *);
extern int my_send(OM_uint32 *, const gss_ctx_id_t, char *, size_t, int *, 
		   int (*)(void *, void *, size_t), void *, void *);
#endif
