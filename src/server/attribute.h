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

#ifndef VOMS_ATTRIBUTE_H
#define VOMS_ATTRIBUTE_H

#include <string>

class attrib {

 public:
  
  std::string str() const;

 public:

  std::string group;
  std::string role;
  std::string cap;

};

extern bool operator<(const attrib& lhs, 
                      const attrib& rhs);

bool operator==(const attrib& lhs,
                const attrib& rhs);

#endif /* __ATTRIBUTE_H */
