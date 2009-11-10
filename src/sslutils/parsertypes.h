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

#ifndef _OLDGAA_PARSERTYPES_H
#define _OLDGAA_PARSERTYPES_H

struct condition {
  char **subjects;
  char *original;
  int positive;
};

#define TYPE_SIGNING   0
#define TYPE_NAMESPACE 1

struct policy {
  char *caname;
  int self;
  int type;
  struct condition **conds;
};

#define SUCCESS_PERMIT    0
#define SUCCESS_DENY      1
#define SUCCESS_UNDECIDED 2

#endif
