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
#ifndef VOMS_PARSERTYPES_H
#define VOMS_PARSERTYPES_H
typedef struct param {
  char *name;
  char *value;
} PARAM;

typedef struct paramlist {
  int current;
  PARAM **params;
} PARAMLIST;

typedef struct vo {
  char *voname;
  char *hostcert;
  char *hostkey;
  int fqansize;
  char **fqans;
  int gasize;
  char **gas;
  int  vomslife;
  char *targets;
  char *uri;
  int   newformat;
  PARAMLIST *params;
} VO;

typedef struct volist {
  int current;
  VO **vos;
} VOLIST;
#endif
