/*********************************************************************
 *
 * Authors: Vincenzo Ciaschini - Vincenzo.Ciaschini@cnaf.infn.it 
 *          Valerio Venturi - Valerio.Venturi@cnaf.infn.it 
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

#include <iostream>
#include "fqan.h"

Fqan::Fqan(const std::string& s)
{
  std::string::size_type pos = s.find("/Role=");
  if (pos != std::string::npos && pos > 0)
  {
    group = s.substr(0, pos);
    role = s.substr(pos+1);
  }
  else group = s;
}

std::string Fqan::str() const
{
  return group + "/Role=" + role;
}

std::string FQANParse(std::string fqan) {

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

std::string parse_fqan(const std::vector<std::string>& fqans)
{
  std::string parsed;
  
  for(std::vector<std::string>::const_iterator i = fqans.begin(); i != fqans.end(); ++i)
  {
    /* check whether fqan is all */
    if(*i == "all" || *i == "ALL")
      return "A";
    
    /* check for presence of capability selection */
    std::string::size_type cap_pos = i->find("/Capability=");
    if(cap_pos!=std::string::npos)
    {
      std::cerr << "capability selection not supported" << std::endl;
      exit(1);
    }
  
    /* check for role selection */
    std::string::size_type role_pos = i->find("/Role=");
    if (role_pos != std::string::npos && role_pos > 0)
      parsed += "B" + i->substr(0, role_pos) + ":" + i->substr(role_pos+6);
    else if (role_pos == 0)
      parsed += "R" + i->substr(role_pos+6);
    else if ((*i)[0] == '/')
      parsed += "G" + i->substr(0);
    
    if(i != (fqans.end() - 1))
      parsed += ",";
  }

  return parsed;
}
