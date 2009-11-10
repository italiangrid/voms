/*********************************************************************
 *
 * Authors: Vincenzo Ciaschini - Vincenzo.Ciaschini@cnaf.infn.it 
 *          Valerio Venturi    - Valerio.Venturi@cnaf.infn.it
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
#include <string>
#include "fqan.h"

class Contact
{

public:

  Contact(const std::string& s) : vo_(""),
                                  fqan_(""),
                                  nick_("")
  {
    /* separate nick from fqan */
    std::string::size_type pos = s.find(':');
    if (pos != std::string::npos)
    {
      nick_ = vo_ = s.substr(0, pos);
      fqan_ = s.substr(pos+1);  
    }
    else
    {
      nick_ = s;
    }
  }
  
  std::string vo() const
  {
    return vo_;
  }
  
  std::string fqan() const
  {
    return fqan_;
  }

  std::string nick() const
  {
    return nick_;
  }

private:

  std::string vo_;
  std::string fqan_;
  std::string nick_;
};
