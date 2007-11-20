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

#ifndef SQLDBWRAP_H
#define SQLDBWRAP_H

#include <string>

extern "C" {
#include <openssl/x509.h>
}

#define ERR_DBERR              1
#define ERR_NO_PARAM           2
#define ERR_NO_MEMORY          3
#define ERR_ACCOUNT_SUSPENDED  4
#define ERR_X509               5
#define ERR_USER_UNKNOWN       6
#define ERR_NO_CA              7
#define ERR_NO_IDDATA          8
#define ERR_NO_DB              9
#define ERR_NO_SESSION        10

#define OPTION_SET_SOCKET   1
#define OPTION_SET_PORT     2
#define OPTION_SET_INSECURE 3

#define OPERATION_GET_ALL                      0
#define OPERATION_GET_ROLE                     1
#define OPERATION_GET_GROUPS                   2
#define OPERATION_GET_GROUPS_AND_ROLE          3
#define OPERATION_GET_ALL_ATTRIBS              4
#define OPERATION_GET_ROLE_ATTRIBS             5
#define OPERATION_GET_GROUPS_ATTRIBS           6
#define OPERATION_GET_GROUPS_AND_ROLE_ATTRIBS  7
#define OPERATION_GET_VERSION                  8
#define OPERATION_GET_USER                     9

class gattrib {
 public:

  std::string name;
  std::string qualifier;
  std::string value;

  std::string str() const { return (qualifier.empty() ? "" : qualifier) + "::" +
      name + "=" + value; }
};

namespace sqliface {

class interface  
{

public:
  virtual ~interface(void) {};
  virtual int error(void) const = 0;
  virtual bool connect(const char *, const char *, const char *, const char *) = 0;
  virtual bool reconnect() = 0;
  virtual void close(void) = 0;
  virtual bool setOption(int option, void *value) = 0;

  virtual bool operation(int operation_type, void *result, ...) = 0;

  virtual interface *getSession() = 0;
  virtual void releaseSession(interface *) = 0;
  
  virtual bool isConnected(void) = 0;
  virtual char *errorMessage(void) = 0;
};

}; // namespace sqliface

extern "C" {
  sqliface::interface *CreateDB();
  int getDBInterfaceVersion();
  int getDBInterfaceVersionMinor();
}

#endif
