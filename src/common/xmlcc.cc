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

extern "C" {
#include "xml.h"
#include "listfunc.h"
#include "errortype.h"
}

#include "vomsxml.h"
#include "errors.h"

std::string XML_Req_Encode(const std::string command, const std::string order,
                          const std::string targets, const int lifetime)
{
  char *ret = XMLEncodeReq(command.c_str(), order.c_str(),
                          targets.c_str(), lifetime);
  std::string res;

  if (ret)
    res = std::string(ret);
  free(ret);

  return res;
}

std::string XML_Ans_Encode(const answer &a)
{
  return XML_Ans_Encode(a.ac, a.errs, a.base64);
}

std::string XML_Ans_Encode(const std::string &ac, const std::vector<errorp> e, bool base64)
{
  return XML_Ans_Encode(ac, "", e, base64);
}

std::string XML_Ans_Encode(const std::string &ac, const std::string &data, const std::vector<errorp> e, bool base64)
{
  struct error **vect = NULL, **tmp;

  for (std::vector<errorp>::const_iterator i = e.begin(); i != e.end(); i++) {
    error *t = alloc_error((*i).num, (*i).message.c_str());
    if (t) {
      tmp = (struct error **)listadd((char **)vect, (char *)t, sizeof(struct error *));
      if (tmp)
        vect = tmp;
      else {
        free(t);
        listfree((char **)vect, (freefn)free_error);
        return "";
      }
    }
    else {
      listfree((char **)vect, (freefn)free_error);
      return "";
    }
  }

  char *ret = XMLEncodeAns(vect, ac.data(), ac.size(), data.data(), data.size(), base64);
  listfree((char **)vect, (freefn)free);
  if (ret) {
    std::string s = std::string(ret);
    free(ret);
    return s;
  }
  else
    return "";
}

bool XML_Req_Decode(const std::string message, request &r)
{
  struct req d;

  d.depth = d.error = d.base64 = 0;
  d.command = NULL;
  d.base64 = 0;

  int ret = XMLDecodeReq(message.c_str(), &d);

  if (ret) {
    r.order    = (d.order   ? std::string(d.order)   : "");
    r.targets  = (d.targets ? std::string(d.targets) : "");
  
    int current = 0;

    if (d.command) {
      while(d.command[current]) {
        r.command.push_back(std::string(d.command[current]));
        current++;
      }  
    }

    r.lifetime = d.lifetime;
    r.base64 = (d.base64 == 1);
    r.version = d.version;

    free(d.order);
    free(d.targets);
    listfree(d.command, free);

  }
  return (ret != 0);

}

bool XML_Ans_Decode(const std::string message, answer &a)
{
  struct ans d;
  d.depth = d.error = 0;

  int ret = XMLDecodeAns(message.c_str(), &d);

  a.ac   = (d.ac  ? std::string(d.ac, d.aclen)      : "");
  a.data = (d.data ? std::string(d.data, d.datalen) : "");
  a.version = d.version;

  struct error **tmp = d.list;
  if (tmp && (*tmp)) {
    while (*tmp) {
      struct errorp e;
      e.num     = (*tmp)->num;
      e.message = (*tmp)->message;

      a.errs.push_back(e);
      tmp++;
    }
  }

  listfree((char **)d.list, (freefn)free_error);
  free(d.data);
  free(d.ac);

  return (ret != 0);
}

bool XML_Ans_Decode(const std::string message,
		    std::string &ac, std::vector<errorp> &errs)
{
  struct answer a;
  bool ret = XML_Ans_Decode(message, a);

  ac   = a.ac;
  errs = a.errs;
  return ret;
}
