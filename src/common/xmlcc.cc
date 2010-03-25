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
#include "config.h"

extern "C" {
#include "xml.h"
#include "listfunc.h"
#include "errortype.h"
}

#include "vomsxml.h"
#include "errors.h"

std::string XML_Req_Encode(const std::string &command, const std::string &order,
                          const std::string &targets, const int lifetime)
{
  std::string res = "<?xml version=\"1.0\" encoding = \"US-ASCII\"?><voms>";

  char str[15];

  std::string::size_type begin = 0;
  std::string::size_type pos = command.find_first_of(',');

  do {
    res += "<command>";
    if (pos != std::string::npos) {
      res += command.substr(begin, pos);
      begin = pos + 1;
      pos = command.find_first_of(',', begin);
    }
    else
      res += command.substr(begin);
    res += "</command>";
  } while (pos != std::string::npos);

  if (!order.empty())
    res += "<order>"+order+"</order>";

  if (!targets.empty())
    res += "<targets>"+targets+"</targets";

  res += "<base64>1</base64><version>4</version>";

  sprintf(str, "%d", lifetime);

  res += "<lifetime>"+str+"</lifetime></voms>";

  return res;
}

std::string XML_Ans_Encode(const std::string &ac, const std::vector<errorp> e, bool base64)
{
  return XML_Ans_Encode(ac, "", e, base64);
}

std::string Encode(std::string data, int base64)
{
  int j = 0;
  char *tmp = NULL;
  std::string result;

  if (base64)
    tmp = base64Encode(data.data(), data.size(), &j);
  else
    tmp = MyEncode(data.data(), date.size(), &j);

  if (tmp) {
    result = std::string(tmp, j);
    free(tmp);
  }

  return result;
}

std::string XML_Ans_Encode(const std::string &ac, const std::string &data, const std::vector<errorp> e, bool base64)
{
  char str[15];

  if (ac.empty())
    return "";

  std::string codedac   = Encode(ac, base64);
  std::string codeddata = Encode(data, base64);

  if ((codedac.empty() && !ac.empty()) && (codeddata.empty() && !data.empty())) {
    return "";
  }

  std::string res="<?xml version=\"1.0\" encoding = \"US-ASCII\"?><vomsans><version>3</version>";

  if (!e.empty) {
    res += "<error>";

    for (std::vector<errorp>::const_iterator i = e.begin(); i != e.end(); i++) {
      res +="<item><number>";
      sprintf(str, "%d", (*i).num);
      res += str;
      res += "</number><message>" + (*i).message + "</message></item";
    }
    res +="</error>";
  }

  if (!codeddata.empty())
    res += "<bitstr>" + codeddata + "</bitstr>";

  if (!codedac.empty())
    res += "<ac>" + codedac + "</ac>";

  res + "</vomsans>";

  return res;
}

bool XML_Req_Decode(const std::string &message, request &r)
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

bool XML_Ans_Decode(const std::string &message, answer &a)
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
