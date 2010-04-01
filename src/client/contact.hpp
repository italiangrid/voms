/*********************************************************************
 *
 * Authors: Vincenzo Ciaschini - Vincenzo.Ciaschini@cnaf.infn.it 
 *          Valerio Venturi    - Valerio.Venturi@cnaf.infn.it
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
