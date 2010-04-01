/*********************************************************************
 *
 * Authors: Vincenzo Ciaschini - Vincenzo.Ciaschini@cnaf.infn.it 
 *          Valerio Venturi - Valerio.Venturi@cnaf.infn.it 
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

#include "config.h"

#include <iostream>
#include <cstdlib>
#include "fqan.h"

std::string parse_fqan(const std::vector<std::string>& fqans)
{
  std::string parsed;
  
  for(std::vector<std::string>::const_iterator i = fqans.begin(); i != fqans.end(); ++i)
  {
    parsed += FQANParse(*i);
    if(i != (fqans.end() - 1))
      parsed += ",";
  }

  return parsed;
}

std::string FQANParse(std::string fqan) 
{
  std::string parsed = fqan;

  /* check if fqan is all */

  if(fqan == "all" || fqan == "ALL")
    parsed = "A";
  else {

    /* check for presence of capability selection */

    std::string::size_type cap_pos = fqan.find("/Capability=");
    if(cap_pos!=std::string::npos) {
      //if(!quiet)
      std::cerr << "capability selection not supported" << std::endl;
      exit(1);
    }

    /* check for role selection*/

    std::string::size_type role_pos = fqan.find("/Role=");
    if (role_pos != std::string::npos && role_pos > 0)
      parsed = "B" + fqan.substr(0, role_pos) + ":" + fqan.substr(role_pos+6);
    else if (role_pos==0)
      parsed = "R" + fqan.substr(role_pos+6);
    else if (fqan[0] == '/')
      parsed = "G" + fqan.substr(0);
  }

  return parsed;
}
