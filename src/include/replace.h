/*********************************************************************
 *
 * Authors: Vincenzo Ciaschini - Vincenzo.Ciaschini@cnaf.infn.it 
 *          Valerio Venturi    - Valerio.Venturi@cnaf.infn.it
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
#ifndef VOMS_REPLACES_H
#define VOMS_REPLACES_H
#include "config.h"

#ifndef HAVE_GLOBUS_OFF_T
#ifdef HAVE_LONG_LONG_T
#define GLOBUS_OFF_T long long
#else
#define GLOBUS_OFF_T long
#endif
#endif

#ifdef __cplusplus
extern "C" {
#endif
#ifndef HAVE_DAEMON
extern int daemon(int, int);
#endif
#ifndef HAVE_SETENV
extern int setenv(const char *, const char *, int);
extern void unsetenv(const char *);
#endif
#ifndef HAVE_STRNDUP
#include <string.h>
extern char *strndup(const char *, size_t);
#endif
#ifdef __cplusplus
}
#endif
#endif /* REPLACES_H */
