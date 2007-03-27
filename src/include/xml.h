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
#ifndef VOMS_XML_H
#define VOMS_XML_H
#include "errortype.h"

#ifdef __cplusplus
extern "C" {
#endif

struct req {
  char *order;
  char **command;
  int  n;
  char *targets;
  char *value;
  int   error;
  int   lifetime;
  int   depth;
};

struct ans {
  char *data;
  int   datalen;
  char *ac;
  int   aclen;
  struct error **list;

  struct error  *err;
  char *value;
  int error;
  int depth;
};

char *XMLEncodeReq(const char *, const char *, const char *, int);
char *XMLEncodeAns(struct error **, const char *, int, const char *, int);
int XMLDecodeReq(const char *, struct req *);
int XMLDecodeAns(const char *, struct ans *);

#ifdef __cplusplus
}
#endif
#endif
