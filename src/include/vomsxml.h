/*********************************************************************
 *
 * Authors: Vincenzo Ciaschini - Vincenzo.Ciaschini@cnaf.infn.it 
 *
 * Copyright (c) Members of the EGEE Collaboration. 2004-2010.
 * See http://www.eu-egee.org/partners/ for details on the copyright holders.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
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
