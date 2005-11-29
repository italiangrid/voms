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

std::string XML_Req_Encode(const request &r)
{
  return XML_Req_Encode(r.command, r.order, r.targets, r.lifetime);
}

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
  return XML_Ans_Encode(a.ac, a.errs);
}

std::string XML_Ans_Encode(const std::string &ac, const std::vector<errorp> e)
{
  return XML_Ans_Encode(ac, "", e);
}

std::string XML_Ans_Encode(const std::string &ac, const std::string &data, const std::vector<errorp> e)
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

  char *ret = XMLEncodeAns(vect, ac.data(), ac.size(), data.data(), data.size());
  listfree((char **)vect, (freefn)free);
  if (ret)
    return std::string(ret);
  else
    return "";
}

bool XML_Req_Decode(const std::string message, request &r)
{
  struct req d;

  d.depth = d.error = 0;

  int ret = XMLDecodeReq(message.c_str(), &d);

  r.order    = (d.order   ? std::string(d.order)   : "");
  r.targets  = (d.targets ? std::string(d.targets) : "");
  r.command  = (d.command ? std::string(d.command) : "");
  r.lifetime = d.lifetime;
  free(d.order);
  free(d.targets);
  free(d.command);

  return (ret != 0);
}

bool XML_Req_Decode(const std::string message, std::string &order,
		    std::string &targets, std::string &command, int &lifetime)
{
  request r;
  bool ret = XML_Req_Decode(message, r);

  order    = r.order;
  targets  = r.targets;
  command  = r.command;
  lifetime = r.lifetime;

  return ret;
}

bool XML_Ans_Decode(const std::string message, answer &a)
{
  struct ans d;
  d.depth = d.error = 0;

  int ret = XMLDecodeAns(message.c_str(), &d);

  a.ac   = (d.ac  ? std::string(d.ac, d.aclen)      : "");
  a.data = (d.data ? std::string(d.data, d.datalen) : "");

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
