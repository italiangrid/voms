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
#ifndef VOMS_XML_H
#define VOMS_XML_H
#include "errortype.h"

struct req {
  struct request *r;
  std::string value;
  int   error;
  int   depth;
};

struct ans {
  struct answer *a;
  std::string *value;
  int error;
  int depth;
};

extern char *XMLEncodeReq(const char *, const char *, const char *, int);
extern char *XMLEncodeAns(struct error **, const char *, int, const char *, int, int);
extern int XMLDecodeReq(const char *, struct req *);
extern int XMLDecodeAns(const char *, struct ans *);
#endif
