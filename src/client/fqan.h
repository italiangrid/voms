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
#ifndef VOMS_CLIENT_FQAN_H
#define VOMS_CLIENT_FQAN_H

#include <string>
#include <vector>

class Fqan
{
  
public:

  Fqan(const std::string& s);
  
  std::string str() const;  


private:

  std::string group;
  std::string role;
  
};


std::string FQANParse(std::string fqan);

std::string parse_fqan(const std::vector<std::string>& fqans);

#endif
