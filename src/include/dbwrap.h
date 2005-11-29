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

#define SQL_DEADLOCK 6000

namespace sqliface {

class interface;
class query;
class resuls;

class DBEXC {

 public:
  
  DBEXC() {}
  DBEXC(std::string str) : s(str) {}
  const std::string what() const { return s; }
 
 private:
  const std::string s;

};

class results 
{

public:

  virtual ~results(void) {};
  virtual const std::string get(int) const = 0;
  virtual const std::string get(const std::string&) const = 0;
  virtual bool valid() const = 0;
  virtual bool next() = 0;
  virtual int size() const = 0;
  virtual const std::string name(int) const = 0;

};

class query 
{

public:

  virtual ~query() {}
  virtual query &operator<<(std::string) = 0;

  virtual results* result(void) = 0;

  virtual void exec(void) = 0;
  virtual int  error(void) const = 0;

};

class interface  
{

public:
  virtual ~interface(void) {};
  virtual int error(void) const = 0;
  virtual void connect(const char *, const char *, const char *, const char *) = 0;
  virtual query* newquery() = 0;

};

}; // namespace sqliface

extern "C" {
  sqliface::interface *CreateDB();
}

#endif
