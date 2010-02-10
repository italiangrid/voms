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
#ifndef VOMS_VOMSXML_H
#define VOMS_VOMSXML_H
#include <string>
#include <vector>

#include "xml.h"
#include "errors.h"

struct request {
  std::string order;
  std::string targets;
  std::vector<std::string> command;
  int lifetime;
  bool base64;
  int version;
};

struct answer {
  std::string data;
  std::string ac;
  std::vector<errorp> errs;
  bool base64;
  int version;
};

std::string XML_Req_Encode(const std::string&, const std::string&, 
                           const std::string&, const int);
std::string XML_Ans_Encode(const std::string&, 
                           const std::vector<errorp>, bool);
std::string XML_Ans_Encode(const std::string&,  const std::string&,
                           const std::vector<errorp>, bool);
bool XML_Req_Decode(const std::string&, request &);
bool XML_Ans_Decode(const std::string&, answer &);
#endif
