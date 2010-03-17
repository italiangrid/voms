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
#ifndef VOMS_DATA_H
#define VOMS_DATA_H

#include <string>

extern bool        acceptable(const char *str);
extern bool        acceptable(std::string s);
extern char *      timestamp(void);
extern std::string stringify(int i, std::string &s);
extern std::string OpenSSLError(bool debug);
extern std::string readfile(std::string filename);
#endif
