
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

#ifndef VOMS_ACCESS_DB_SQL_H
#define VOMS_ACCESS_DB_SQL_H

#include <attribute.h>
#include <openssl/bn.h>
#include <string>
#include <vector>

/*
 * This module contains the functions that execute queries on the VOMS database.
 * All access is done via the layer of indirection provided by the functions in
 * the mysql_wrap.c module.
 */

extern BIGNUM *get_serial(int code, 
                          const std::string &dbname, 
                          const std::string &username, 
                          const std::string &contactstring,
                          int port,
                          const std::string& socket,
                          const char * password);

extern int get_version(const std::string& dbname, 
                       const std::string& username, 
                       const std::string& contactstring, 
                       int port,
                       const std::string& socket, 
                       const char * password);

extern bool special(const std::string& dn,
                    const std::string& ca,
                    const char * request,
                    const std::string& dbname,
                    const std::string& username,
                    const std::string& contactstring,
                    int port,
                    const std::string& socket,
                    const char * password,
                    std::string & result);

extern bool getlist(const std::string& dn,
                    const std::string& ca,
                    const std::string& dbname,
                    const std::string& username,
                    const std::string& contactstring,
                    int port,
                    const std::string& socket,
                    const char * password,
                    std::string & result);

extern bool getattribs(const std::string& dn,
                       const std::string& ca,
                       const std::string& dbname,
                       const std::string& username,
                       const std::string& contactstring,
                       int port,
                       const std::string& socket,
                       const char * password,
                       std::string & result);

extern bool listspecial(const std::string& dbname,
                        const std::string& username,
                        const std::string& contactstring,
                        int port,
                        const std::string& socket,
                        const char * password,
                        std::string& result);

extern bool get_all(const std::string& dn,
                    const std::string& ca,
                    const std::string& dbname,
                    const std::string& username,
                    const std::string& contactstring,
                    int port,
                    const std::string& socket,
                    const char * password,
                    std::vector<attrib>& result);

extern bool get_role(const std::string& dn,
                     const std::string& ca,
                     const char * role,
                     const std::string& dbname,
                     const std::string& username,
                     const std::string& contactstring,
                     int port,
                     const std::string& socket,
                     const char * password,
                     std::vector<attrib>& result);

extern bool get_group(const std::string& dn,
                      const std::string& ca,
                      const char * group,
                      const std::string& dbname,
                      const std::string& username,
                      const std::string& contactstring,
                      int port,
                      const std::string& socket,
                      const char * password,
                      std::vector<attrib>& result);

extern bool get_group_and_role(const std::string& dn,
                               const std::string& ca,
                               const char * group,
                               const std::string& dbname,
                               const std::string& username,
                               const std::string& contactstring,
                               int port,
                               const std::string& socket,
                               const char * password,
                               std::vector<attrib>& result);

extern bool get_user_attributes(const std::string& dn,
                                const std::string& ca,
                                const std::string& dbname,
                                const std::string& username,
                                const std::string& contactstring,
                                int port,
                                const std::string& socket,
                                const char * password,
                                std::vector<gattrib>& result);

extern bool get_group_attributes(const std::string& dn,
                                 const std::string& ca,
                                 const char * group,
                                 const std::string& dbname,
                                 const std::string& username,
                                 const std::string& contactstring,
                                 int port,
                                 const std::string& socket,
                                 const char * password,
                                 std::vector<gattrib>& result);

extern bool get_group_and_role_attributes(const std::string& dn,
                                          const std::string& ca,
                                          const char * group,
                                          const std::string& dbname,
                                          const std::string& username, 
                                          const std::string& contactstring,
                                          int port, 
                                          const std::string& socket, 
                                          const char * password,
                                          std::vector<gattrib>& result);

#endif
