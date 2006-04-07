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

#include <attribute.h>

std::string attrib::str() const {

  std::string tmp = group;
  if(!role.empty())
    tmp += "/Role=" + role;
  if(!cap.empty())
    tmp += "/Capability=" + cap;
  
  return tmp;
}

bool operator<(const attrib &lhs, 
               const attrib &rhs)
{
  if (lhs.group < rhs.group)
    return true;
  if (lhs.group == rhs.group)
    if (lhs.role < rhs.role)
      return true;
  return false;
}

bool operator==(const attrib &lhs, 
                const attrib &rhs)
{
  return ((lhs.group == rhs.group) && (lhs.role == rhs.role) && (lhs.cap == rhs.cap));
}
