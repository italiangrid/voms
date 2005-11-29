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
#ifndef VOMS_VOMSXML_H
#define VOMS_VOMSXML_H
#include <string>
#include <vector>

#include "xml.h"
#include "errors.h"

struct request {
  std::string order;
  std::string targets;
  std::string command;
  int lifetime;
};

struct answer {
  std::string data;
  std::string ac;
  std::vector<errorp> errs;
};

std::string XML_Req_Encode(const request &);
std::string XML_Req_Encode(const std::string, const std::string, 
                           const std::string, const int);
std::string XML_Ans_Encode(const answer &);
std::string XML_Ans_Encode(const std::string&, 
                           const std::vector<errorp>);
std::string XML_Ans_Encode(const std::string&,  const std::string&,
                           const std::vector<errorp>);
bool XML_Req_Decode(const std::string, request &);
bool XML_Req_Decode(const std::string, std::string &, std::string &, int &);
bool XML_Ans_Decode(const std::string, answer &);
bool XML_Ans_Decode(const std::string, std::string &,
                    std::vector<errorp> &);
#endif
