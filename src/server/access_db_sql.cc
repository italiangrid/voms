/*********************************************************************
 *
 * Authors: Vincenzo Ciaschini - Vincenzo.Ciaschini@cnaf.infn.it 
 *          Valerio Venturi - valerio.venturi@cnaf.infn.it
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
/*
 * This module contains the functions that execute queries on the VOMS database.
 * All access is done via the layer of indirection provided by the functions in
 * the dbwrap.c module.
 */
#include "config.h"

extern "C" {
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
}

#include <iostream>
#include <string>
#include <memory>

#include <list>
#include <set>
#include "dbwrap.h"
#include "access_db_sql.h"
#include "data.h"

#include <openssl/bn.h>

#if (__GNUC__ >= 3)
#include <ext/hash_set>
using  __gnu_cxx::hash_set;
#else
#include <hash_set>
#endif

extern "C" {
#include "log.h"
extern void *logh;
}

extern bool compat_flag;

#define CATCH \
catch (sqliface::DBEXC& e) \
{ \
  LOGM(VARP, logh, LEV_ERROR, T_REQUEST, "DBEXC : %s", e.what().c_str()); \
} \
  
typedef std::set<std::string> datahash;

typedef sqliface::interface* (*cdb)();
typedef void (*c)(sqliface::interface *, const char *, const char *, const char *, int, const char *, const char *);

extern cdb NewDB;
extern c   connect_with_port_and_socket;

static bool get_group_and_role_real(const std::string &dn, 
                                    const std::string &ca, 
                                    const std::string &dbname, 
                                    const std::string &username,
                                    const std::string &contactstring,
                                    int port,
                                    const std::string& socket,
                                    const char *password, 
                                    const std::string &query, 
                                    std::vector<attrib> &result);

static bool get_attributes_real(const std::string &dn,
                                const std::string &ca, 
                                const std::string &dbname, 
                                const std::string &username,
                                const std::string &contactstring,
                                int port,
                                const std::string& socket,
                                const char *password, 
                                const std::string &query, 
                                std::vector<gattrib> &result);

static bool simple_query(const std::string &dbname, 
                         const std::string &username,
                         const std::string &contactstring,
                         int port, const std::string& socket,
                         const char *password, const std::string &query,
                         const char *fieldname, std::string &result);

static bool get_fields(const std::string &dbname, const std::string &username, 
                       const std::string &contactstring, int port, 
                       const std::string& socket, const char *password, 
                       const std::string &query, std::string &result);

static bool get_group_and_role_real0(sqliface::interface *db, const std::string &dn,
                                     const std::string &ca,
                                     const std::string &query,
                                     std::vector<attrib> &results, datahash &map);

static bool get_attributes_real0(sqliface::interface *db, const std::string &dn,
                                 const std::string &ca,
                                 const std::string &query,
                                 std::vector<gattrib> &results, datahash &map);

static bool simple_query0(sqliface::interface *db, const std::string &query, const char *fieldname, std::string &result);

/*
 * Function:
 *   subst(format, user, ca)
 *
 * Description:
 *   This function inserts into the 'format' std::string the values of 'user' and
 *   'ca'.
 *
 * Parameters:
 *   'format' - This is the prototype std::string. It may contain the substrings
 *              '$user' and '$ca', that are substituted respectively with the
 *              content of the 'user' and 'ca' arguments.
 *   'user'   - This is the value to substitute in place of the '$user' string.
 *   'ca'     - This is the value to substitute in place of the '$ca' string.
 *
 * Result:
 *   Failure:
 *     NULL.
 *   Success:
 *     A pointer to a new std::string with the values substituted. It must be manually
 *     freed when it is no longer used.
 *
  * NOTE:
 *   All the substitutions are performed at the same time.
 */
static bool
subst(std::string &format, const std::string &user, const std::string &ca)
{
  int doca;

  if (format.empty() || user.empty() || ca.empty())
    return false;

  /*
   * Inefficient, but will do for now.
   */

  unsigned int userp = format.find("$user");
  unsigned int cap = format.find("$ca");

  while (userp != format.npos && cap != format.npos) {

    /*
     * Selects the first substitution to perform.
     */
    if (cap < userp)
      doca = 1;
    else
      doca = 0;
    if (!cap)
      doca = 0;
    if (!userp)
      doca = 1;

    /*
     * Substitutes an element.
     */
    switch (doca) {
    case 0:
      format.replace(userp, 5, user);
      break;

    case 1:
      format.replace(cap, 3, ca);
      break;

    default:
      /* should never happen */
      return false;
    }

    userp = format.find("$user");
    cap = format.find("$ca");
  }

  return true;
}

/*
 * Function:
 *   special(dn, ca, request, dbname, username, password)
 *
 * Description:
 *   This function retireves a query from the query database and then executes
 *   it.
 *
 * Parameters:
 *   'dn'       - The subject of the user's certificate.
 *   'ca'       - The subject of the CA that issued the user's certificate.
 *   'request'  - The request that must be performed. In the format "S<num>" where
 *                the "S" part is supposed to having been verified by the caller.
 *   'dbname'   - The name of the VOMS database.
 *   'username' - The username of the user that must access the VOMS database.
 *   'password' - The password of the user that must access the VOMS database.
 *
 * Result:
 *   Failure:
 *     NULL. Furthermore, the 'data' blob is erased.
 *   Success:
 *     The blob with the requested data.
 *
 * NOTE:
 *   The data is returned as a list of "<fieldname>: <value>" lines for each
 *   field. Multiple records are added one after another.
 */
bool
special(const std::string &dn, const std::string &ca,  const char *request, 
        const std::string &dbname, const std::string &username, 
        const std::string& contactstring, int port, const std::string& socket, 
        const char *password, std::string &result)
{
  if (dn.empty() || ca.empty() || !request || dbname.empty() ||
      username.empty() || !password)
    return false;

  /* Verifies if the input is acceptable */
  if (acceptable(request)) {
    std::string query  = std::string("SELECT query FROM queries WHERE qid = ") + request;
    std::string realquery;

    /* Retrieves the query */
    if (simple_query(dbname, username, contactstring, port, socket, password, query, "query", realquery))
      if (subst(realquery, dn, ca))
        return get_fields(dbname, username, contactstring, port, socket, password, realquery, result);
  }

  return false;
}

bool
getlist(const std::string& dn, const std::string& ca, const std::string& dbname,
        const std::string& user, const std::string& contact, 
        int port, const std::string& socket,const char *password,
        std::string& result)
{
  if (dn.empty() || ca.empty() || dbname.empty() || user.empty() || 
      contact.empty() || !password)
    return false;
  	 
  std::string query = std::string("SELECT dn FROM groups");
  	 
  if (get_fields(dbname, user, contact, port, socket, password, "SELECT dn FROM groups", result))
    return get_fields(dbname, user, contact, port, socket, password, "SELECT role FROM roles", result);
  return false;
}

bool getattribs(const std::string& dn, const std::string& ca, const std::string& dbname,
                const std::string& user, const std::string& contact, 
                int port, const std::string& socket,const char *password,
                std::string& result)
{
  std::string query = std::string("SELECT groups.dn as groupname, role, capability, groups.gid "
                                  "FROM groups, usr, ca, m "
                                  "left join roles on roles.rid = m.rid "
                                  "left join capabilities on capabilities.cid = m.cid "
                                  "WHERE groups.gid = m.gid AND ") 
    + (compat_flag ? "usr.uid = m.uid AND " : "usr.userid = m.userid AND ") +
    "usr.ca  = ca.cid AND "
    "ca.ca = \'" + ca + "\' AND "
    "usr.dn = \'" + dn + "\'";
  
  return get_fields(dbname, user, contact, port, socket, password, query, result);
}

/*
 * Function:
 *   listspecial(dbname, username, password)
 *
 * Description:
 *   This function returns a blob containing the text of all the special queries.
 *
 * Parameters:
 *   'dbname'   - The name of the VOMS database.
 *   'username' - The username of the user that must access the VOMS database.
 *   'password' - The password of the user that must access the VOMS database.
 *
 * Result:
 *   Failure:
 *     NULL. Furthermore, the 'data' blob is erased.
 *   Success:
 *     The blob with the requested data.
 */
bool
listspecial(const std::string &dbname, const std::string &username,
            const std::string &contactstring, 
            int port, const std::string& socket,const char *password, 
            std::string &result)
{
  return get_fields(dbname, username, contactstring, port, socket, password, "SELECT qid, query FROM queries", result);
}

/*
 * Function:
 *   get_all(dn, ca, dbname, username, password)
 *
 * Description:
 *   This function creates a SQL query that retrieves informations about
 *   the groups and roles to which the user belongs.
 *
 * Parameters:
 *   'username' - The username used for database login.
 *   'password' - The password used for database login.
 *   'dbname'   - The database name.
 *   'dn'       - Distinguished Name of the user's certificate.
 *   'ca'       - Distinguished Name of the CA that issued the user's
 *                certificate.
 *
 * Return:
 *   Success - 
 *     The blob with the requested data.
 *   Failure -
 *     NULL.
 */
bool
get_all(const std::string &dn, const std::string &ca, 
        const std::string &dbname, const std::string &username, 
        const std::string &contactstring,	
        int port, const std::string& socket,const char *password, 
        std::vector<attrib> &result)
{
  if (ca.empty() || dn.empty())
    return false;

  std::string query = std::string("SELECT usr.dn as username, role, groups.dn as groupname, capability, groups.gid "
    "FROM groups, usr, ca, m "
    "left join roles on roles.rid = m.rid "
    "left join capabilities on capabilities.cid = m.cid "
    "WHERE groups.gid = m.gid AND ") + 
    (compat_flag ? "usr.uid = m.uid AND " : "usr.userid = m.userid AND ") +
    "usr.ca  = ca.cid AND "
    "ca.ca = \'" + ca + "\' AND "
    "usr.dn = \'" + dn + "\'";

  return get_group_and_role_real(dn, ca, dbname, username, contactstring, port, socket, password, query, result);
}


/*
 * Function:
 *   get_role(dn, ca, role, dbname, username, password)
 *
 * Description:
 *   This function creates a SQL query that retrieves informations about
 *   the groups and roles to which the user belongs, limiting the results
 *   to the role specified.
 * Parameters:
 *   'dn'       - Distinguished Name of the user's certificate.
 *   'ca'       - Distinguished Name of the CA that issued the user's
 *                certificate.
 *   'role'     - The role the user requested.
 *   'username' - The username used for database login.
 *   'password' - The password used for database login.
 *   'dbname'   - The database name.
 *
 * Return:
 *   Success - 
 *     The blob with the requested data.
 *   Failure -
 *     NULL.
 */
bool
get_role(const std::string &dn, const std::string &ca, const char *role,
         const std::string &dbname, const std::string &username, 
         const std::string& contactstring, 
         int port, const std::string& socket, const char *password,
         std::vector<attrib> &result)
{
  if (dn.empty() || ca.empty() || !role || dbname.empty() || username.empty() || !password || !acceptable(role))
    return false;

  std::string query = std::string("SELECT usr.dn as username, role, groups.dn as groupname, capability, groups.gid "
    "FROM groups, usr, ca, m "
    "left join roles on roles.rid = m.rid "
    "left join capabilities on capabilities.cid = m.cid "
    "WHERE groups.gid = m.gid AND ") +
    (compat_flag ? "usr.uid = m.uid AND " : "usr.userid = m.userid AND ") +
    "roles.role = \'" + role + "\' AND "
    "usr.ca  = ca.cid AND "
    "ca.ca = \'" + ca + "\' AND "
    "usr.dn = \'" + dn + "\'";

  return get_group_and_role_real(dn, ca, dbname, username, contactstring, port, socket, password, query, result);
}

/*
 * Function:
 *   get_group(dn, ca, group, dbname, username, password)
 *
 * Description:
 *   This function creates a SQL query that retrieves informations about
 *   the groups and roles to which the user belongs, limiting the results
 *   to the group specified.
 * Parameters:
 *   'dn'       - Distinguished Name of the user's certificate.
 *   'ca'       - Distinguished Name of the CA that issued the user's
 *                certificate.
 *   'group'    - The group the user requested.
 *   'username' - The username used for database login.
 *   'password' - The password used for database login.
 *   'dbname'   - The database name.
 *
 * Return:
 *   Success - 
 *     The blob with the requested data.
 *   Failure -
 *     NULL.
 */
bool
get_group(const std::string &dn, const std::string &ca, const char *group,
          const std::string &dbname, const std::string &username,
          const std::string &contactstring, int port,
          const std::string& socket,const char *password,
          std::vector<attrib> &result)
{
  if (dn.empty() || ca.empty() || !group || dbname.empty() || username.empty() || !password || !acceptable(group))
    return false;

  std::string query = std::string("SELECT usr.dn as username, role, groups.dn as groupname, capability, groups.gid "
                                  "FROM groups, usr, ca, m "
                                  "left join roles on roles.rid = m.rid "
                                  "left join capabilities on capabilities.cid = m.cid "
                                  "WHERE groups.gid = m.gid AND ") +
    (compat_flag ? "usr.uid = m.uid AND " : "usr.userid = m.userid AND ") +
    "groups.dn = \'" + group + ("\' AND "
                                "usr.ca  = ca.cid AND "
                                "ca.ca = \'" + ca + "\' AND "
                                "usr.dn = \'" + dn + "\' AND "
                                "m.rid is NULL");

  return get_group_and_role_real(dn, ca, dbname, username, contactstring, port, socket, password, query, result);
}

/*
 * Function:
 *   get_group_and_role(dn, ca, message, dbname, username, password)
 *
 * Description:
 *   This function creates a SQL query that retrieves informations about
 *   the groups and roles to which the user belongs, limiting the results
 *   to the group and role specified.
 * Parameters:
 *   'dn'       - Distinguished Name of the user's certificate.
 *   'ca'       - Distinguished Name of the CA that issued the user's
 *                certificate.
 *   'message'  - The group and role the user requested, in the format
 *                "Bgroup:role".
 *   'username' - The username used for database login.
 *   'password' - The password used for database login.
 *   'dbname'   - The database name.
 *
 * Return:
 *   Success - 
 *     The blob with the requested data.
 *   Failure -
 *     NULL.
 */
bool
get_group_and_role(const std::string &dn, const std::string &ca, 
                   const char *group, const std::string &dbname,
                   const std::string &username, 
                   const std::string &contactstring,
                   int port, const std::string& socket,
                   const char *password, std::vector<attrib> &result)
{
  char *role;

  if (dn.empty() || ca.empty() || !group || dbname.empty() || username.empty() || !password)
    return false;

  char *argument = strdup(group);

  if (!argument || !(role = strchr(argument,':')))
    return false;

  *role++ = '\0';

  if (!acceptable(argument) || !acceptable(role))
    return false;

  std::string query = std::string("SELECT usr.dn as username, role, groups.dn as groupname, capability, groups.gid "
                                  "FROM groups, usr, ca, m "
                                  "left join roles on roles.rid = m.rid "
                                  "left join capabilities on capabilities.cid = m.cid "
                                  "WHERE groups.gid = m.gid AND ") +
    (compat_flag ? "usr.uid = m.uid AND " : "usr.userid = m.userid AND ") +
    "roles.role = \'" + role + "\' AND "
    "groups.dn = \'" + argument + "\' AND "
    "usr.ca  = ca.cid AND "
    "ca.ca = \'" + ca + "\' AND "
    "usr.dn = \'" + dn + "\'";
  
  free(argument);
  return get_group_and_role_real(dn, ca, dbname, username, contactstring, port, socket, password, query, result);
}

/*
 * Function:
 *   get_group_and_role_real(dbname, username, password, query)
 *
 * Description:
 *   This function executes one of the get_* queries and returns the results
 *   in a blob.
 *
 * Parameters:
 *   'dbname'   - The database name.
 *   'username' - The username used for database login.
 *   'password' - The password used for database login.
 *   'query'    - The query to execute.
 *
 * Return:
 *   Success - 
 *     The blob with the requested data.
 *   Failure -
 *     NULL.
 */
static bool
get_group_and_role_real(const std::string &dn, const std::string &ca,
                        const std::string &dbname, const std::string &username,
                        const std::string &contactstring, 
                        int port, const std::string& socket,const char *password,
                        const std::string &query,	std::vector<attrib> &results)
{
  std::string additional = std::string(" SELECT usr.dn as username, role, groups.dn as groupname, capability, groups.gid "
                                       "FROM groups, usr, ca, m "
                                       "left join roles on roles.rid = m.rid "
                                       "left join capabilities on capabilities.cid = m.cid "
                                       "WHERE groups.gid = m.gid AND ") +
    (compat_flag ? "usr.uid = m.uid AND " : "usr.userid = m.userid AND ") +
    "groups.must IS NOT NULL AND "
    "usr.ca  = ca.cid AND "
    "ca.ca = \'" + ca + "\' AND "
    "usr.dn = \'" + dn + "\' AND "
    "m.rid is NULL";
  
  if (dbname.empty() || username.empty() || !password || query.empty())
    return false;
  
  try
  {
    std::auto_ptr<sqliface::interface> db(NewDB());
    if(connect_with_port_and_socket)
      connect_with_port_and_socket(db.get(), dbname.c_str(), contactstring.c_str(), username.c_str(), port, (!socket.empty() ? socket.c_str() : NULL), password);
    else 
      db->connect(dbname.c_str(), contactstring.c_str(), username.c_str(), password);

    std::auto_ptr<sqliface::query> q(db->newquery());

    *q << "SET TRANSACTION ISOLATION LEVEL SERIALIZABLE";
    q->exec();

    datahash map;

    LOGM(VARP, logh, LEV_DEBUG, T_REQUEST, "ORIGINAL: %s", query.c_str());
    bool ok = get_group_and_role_real0(db.get(), dn, ca, query, results, map);
    
    LOGM(VARP, logh, LEV_DEBUG, T_REQUEST, "NEW: %s", additional.c_str());
    bool ok2 = get_group_and_role_real0(db.get(), dn, ca, additional, results, map);
    
    *q << "ROLLBACK";
    q->exec();
    
    return ok && ok2;
  }
  CATCH

  return false;
}


static bool
get_group_and_role_real0(sqliface::interface *db, const std::string &dn,
                         const std::string &ca, const std::string &query,
                         std::vector<attrib> &results, datahash &map)
{
  std::string res;
  bool flag = false;

  if (query.empty())
    return false;

  try {
    std::auto_ptr<sqliface::query> q(db->newquery());

    LOGM(VARP, logh, LEV_DEBUG, T_REQUEST, "QUERY: %s", query.c_str());
    
    *q << query.c_str();

    std::auto_ptr<sqliface::results> r(q->result());

    std::string group;

    std::vector<std::string> v;

    while (r->valid()) 
    {
      attrib rec;
      group = r->get("GID");
      
      std::string record;

      rec.group = r->get("GROUPNAME");
      rec.role  = r->get("ROLE");
      rec.cap   = r->get("CAPABILITY");
      record = "GROUP: " + rec.group + "\nROLE: " + rec.role + "\nCAP: " + rec.cap + "\n";
    
      /* Safety: if groups construct a cyclic structure, break it. */
      if (map.find(record) == map.end()) 
      {
        map.insert(record);
        v.push_back(group);
        results.push_back(rec);
      }
      
      (void)r->next();
    }

    flag = true;
  }
  CATCH

  if (!map.empty())
    return flag;
  else
    return false;
}

/*
 * Function:
 *   get_fields(dbname, username, password, query)
 *
 * Description:
 *   This function executes the query given in its 'query' argument,
 *   and then encodes the resulting table in blob. See special() for the
 *   exact format of the blob.
 *
 * Parameters:
 *   'dbname'   - The database name.
 *   'username' - The username used for database login.
 *   'password' - The password used for database login.
 *   'query'    - The query to execute.
 *
 * Return:
 *   Success - 
 *     The blob with the requested data.
 *   Failure -
 *     NULL.
 */
static bool
get_fields(const std::string &dbname, const std::string &username, 
           const std::string &contactstring, 
           int port, const std::string& socket, const char *password,
           const std::string &query, std::string &result)
{
  std::string res;

  if (dbname.empty() || username.empty() || !password || query.empty())
    return false;

  try {

    std::auto_ptr<sqliface::interface> db(NewDB());
    if(connect_with_port_and_socket)
      connect_with_port_and_socket(db.get(), dbname.c_str(), contactstring.c_str(), username.c_str(), port, (!socket.empty() ? socket.c_str() : NULL), password);
    else 
      db->connect(dbname.c_str(), contactstring.c_str(), username.c_str(), password);

    std::auto_ptr<sqliface::query> q(db->newquery());

    *q << query.c_str();

    std::auto_ptr<sqliface::results> r(q->result());

    while (r->valid()) {
      int fields = r->size();
      for (int index = 0; index < fields; index++)
        res += r->name(index) + ": " + r->get(index) + "\n";
      (void)r->next();
    }

    result += res;
    return true;
  }
  CATCH

  return false;
}

/*
 * Function:
 *   simple_query(dbname, username, password, query, result)
 *
 * Description:
 *   This function executes the query given in its 'query' argument,
 *   and then returns the content of the 'result' field of the first row.
 *
 * Parameters:
 *   'dbname'    - The database name.
 *   'username'  - The username used for database login.
 *   'password'  - The password used for database login.
 *   'query'     - The query to execute.
 *   'fieldname' - The name of the field you are interested in.
 *
 * Return:
 *   Success - 
 *     A std::string with the requested data.
 *   Failure -
 *     NULL.
 */
static bool
simple_query(const std::string &dbname, const std::string &username,
             const std::string &contactstring, 
             int port, const std::string& socket,const char *password, 
             const std::string &query, const char *fieldname, 
             std::string &result)
{
  if (dbname.empty() || username.empty() || !password || 
      !fieldname || query.empty())
    return false;

  try {

    std::auto_ptr<sqliface::interface> db(NewDB());
    if(connect_with_port_and_socket)
      connect_with_port_and_socket(db.get(), dbname.c_str(), contactstring.c_str(), username.c_str(), port, (!socket.empty() ? socket.c_str() : NULL), password);
    else 
      db->connect(dbname.c_str(), contactstring.c_str(), username.c_str(), password);

    return simple_query0(db.get(), query, fieldname, result);
  }
  CATCH

  return false;
}

static bool
simple_query0(sqliface::interface *db, const std::string &qq,
              const char *fieldname, std::string &result)
{
  if (!fieldname || qq.empty())
    return false;

  bool res = false;
  LOG(logh, LEV_DEBUG, T_REQUEST, qq.c_str());
  
  try {
    
    std::auto_ptr<sqliface::query> q (db->newquery());

    *q << qq.c_str();
    q->exec();
    
    std::auto_ptr<sqliface::results> r(q->result());

    if (r->valid()) {
      result = r->get(fieldname);
      res = true;
      (void)r->next();
    }
  }
  CATCH

    return res;
}

BIGNUM *get_serial(int code, const std::string &dbname, 
                   const std::string &username, 
                   const std::string &contactstring,
                   int port, const std::string& socket,
                   const char *password)
{

  if (dbname.empty() || username.empty() || !password)
    return NULL;
  
  char codenum[6];
  sprintf(codenum,"%04x",code);

  try {

    std::auto_ptr<sqliface::interface> db(NewDB());
    if(connect_with_port_and_socket)
      connect_with_port_and_socket(db.get(), dbname.c_str(), contactstring.c_str(), username.c_str(), port, (!socket.empty() ? socket.c_str() : NULL), password);
    else 
      db->connect(dbname.c_str(), contactstring.c_str(), username.c_str(), password);

    std::auto_ptr<sqliface::query> q3(db->newquery());
    *q3 << "COMMIT";
    
    std::auto_ptr<sqliface::query> q2(db->newquery());
    
    std::auto_ptr<sqliface::query> q(db->newquery());

    do {

      try {
        
        std::auto_ptr<sqliface::query> q(db->newquery());
        *q << "SET TRANSACTION ISOLATION LEVEL SERIALIZABLE";
        LOG(logh, LEV_DEBUG, T_REQUEST, "SET TRANSACTION ISOLATION LEVEL SERIALIZABLE");
        q->exec();
    
        *q << "SELECT seq FROM seqnumber";
        LOG(logh, LEV_DEBUG, T_REQUEST, "SELECT seq FROM seqnumber");
        std::auto_ptr<sqliface::results> r(q->result());

        if (!r->valid()) {
          std::auto_ptr<sqliface::query> q4(db->newquery());
          *q4 << "ROLLBACK;";
          LOG(logh, LEV_DEBUG, T_REQUEST, "ROLLBACK");
          q4->exec();
          return NULL;
        }
        
        std::string result = r->get("SEQ");
        
        while (r->valid()) 
          (void)r->next();

        BIGNUM *b=NULL;
        if (BN_hex2bn(&b, result.c_str())) {
          if (BN_add(b, b, BN_value_one())) {
          
            char *str = BN_bn2hex(b);
            std::string realstr = std::string(str);
        
            std::string qq = std::string("UPDATE seqnumber SET seq=\'") + str + "\'";

            *q2 << qq;
        
            LOG(logh, LEV_DEBUG, T_REQUEST, qq.c_str());
            q2->exec();
            LOG(logh, LEV_DEBUG, T_REQUEST, "COMMIT");
            q3->exec();
          
            free(str);
       
            realstr += std::string(codenum);
            if (realstr.size() > 40)
              realstr = realstr.substr(realstr.size()-20);
            BN_free(b);
            b = NULL;
            if (BN_hex2bn(&b,realstr.c_str()))
              return b;
            else
              return NULL;
          }
          BN_free(b);
        }
        
        std::auto_ptr<sqliface::query> q5(db->newquery());
        *q5 << "ROLLBACK";
        LOG(logh, LEV_DEBUG, T_REQUEST, "ROLLBACK");
        q5->exec();
        
      }
      
      catch(sqliface::DBEXC& e) {
        
        LOGM(VARP, logh, LEV_ERROR, T_REQUEST, "DBEXC : %s", e.what().c_str()); 
        
        std::auto_ptr<sqliface::query> q5(db->newquery());
        *q5 << "ROLLBACK";
        LOG(logh, LEV_DEBUG, T_REQUEST, "ROLLBACK");
        q5->exec();
      }

    } while(q2->error() == SQL_DEADLOCK);
    
  }
  CATCH
    
  return NULL;
}

int get_version(const std::string &dbname, const std::string &username, 
                const std::string &contactstring, int port, 
                const std::string& socket, const char * password)
{
  if (dbname.empty() || username.empty() || !password)
    return 0;
  
  try 
  {
    std::auto_ptr<sqliface::interface> db(NewDB());

    if(connect_with_port_and_socket)
      connect_with_port_and_socket(db.get(), dbname.c_str(), contactstring.c_str(), username.c_str(), port, (!socket.empty() ? socket.c_str() : NULL), password);
    else 
      db->connect(dbname.c_str(), contactstring.c_str(), username.c_str(), password);

    std::auto_ptr<sqliface::query> q(db->newquery());
    
    *q << "SET TRANSACTION ISOLATION LEVEL SERIALIZABLE";
    q->exec();

    *q << "SELECT version FROM version";
    
    std::auto_ptr<sqliface::results> r(q->result());

    if (!r->valid()) 
    {
      std::auto_ptr<sqliface::query> q2(db->newquery());
      *q2 << "ROLLBACK";
      q2->exec();
      
      return 0;
    }

    std::string result = r->get("VERSION");

    while (r->valid())
      (void)r->next();

    std::auto_ptr<sqliface::query> q2(db->newquery());
    *q2 << "ROLLBACK";
    q2->exec();
    
    return atoi(result.c_str());
  }
  CATCH

  return 0;
}













bool
get_group_attributes(const std::string &dn, const std::string &ca,
                     const char *group,
                     const std::string &dbname, const std::string &username, const std::string &contactstring,
                     int port, const std::string& socket, const char *password,
                     std::vector<gattrib> &result)
{
  if (dn.empty() || ca.empty() || !group || dbname.empty() || username.empty() || !password)
    return false;

  // compose query

  std::string query = std::string("SELECT usr.dn as username, role, groups.dn as groupname, Attributes.a_name, groups.gid "
                                  "FROM usr INNER JOIN ca ON usr.ca=ca.cid "
                                  "INNER JOIN m ON ") + (compat_flag ? "usr.uid = m.uid" : "usr.userid = m.userid ") +
    "INNER JOIN groups ON m.gid=groups.gid "
    "LEFT JOIN roles on roles.rid = m.rid "
    "INNER JOIN Group_attrs on groups.gid = Group_attrs.g_id "
    "INNER JOIN Attributes on Attributes.a_id = Group_attrs.a_id "
    "WHERE groups.dn = \'" + group + "\' AND "
    "ca.ca = \'" + ca + "\' AND "
    "usr.dn = \'" + dn + "\' AND "
    "m.rid is NULL";
  
  return get_attributes_real(dn, ca, dbname, username, contactstring, port, socket, password, query, result);
}

bool
get_role_attributes(const std::string &dn, const std::string &ca,
                    const char *role,
                    const std::string &dbname, const std::string &username, const std::string &contactstring,
                    int port, const std::string& socket, const char *password,
                    std::vector<gattrib> &result)
{
  if (dn.empty() || ca.empty() || !role || dbname.empty() || username.empty() || !password)
    return false;
  
  // separate group and role in group:role syntax
  
  if (!acceptable(role))
    return false;

  // compose query
  std::string query = std::string("SELECT usr.dn as username, role, groups.dn as groupname, capability, groups.gid, Attributes.a_name, Role_attrs.a_value "
                                  "FROM usr INNER JOIN ca ON usr.ca=ca.cid"
                                  "INNER JOIN m ON ") + (compat_flag ? "usr.uid = m.uid" : "usr.userid = m.userid ") +
    "INNER JOIN groups ON m.gid=groups.gid"
    "LEFT JOIN roles ON roles.rid = m.rid "
    "LEFT JOIN capabilities ON capabilities.cid = m.cid "
    "INNER JOIN Role_attrs on groups.gid = Role_attrs.g_id "
    "INNER JOIN Attributes on Attributes.a_id = Role_attrs.a_id "
    "WHERE Role_attrs.r_id = roles.rid AND "
    "roles.role = \'" + role + "\' AND "
    "ca.ca = \'" + ca + "\' AND "
    "usr.dn = \'" + dn + "\'";

  // execute query
  return get_attributes_real(dn, ca, dbname, username, contactstring, port, socket, password, query, result);
}

bool
get_all_attributes(const std::string &dn, const std::string &ca,
                   const std::string &dbname, const std::string &username, const std::string &contactstring,
                   int port, const std::string& socket, const char *password,
                   std::vector<gattrib> &result)
{
  if (dn.empty() || ca.empty() || dbname.empty() || username.empty() || !password)
    return false;
  
  // compose query
  std::string query = std::string("SELECT usr.dn as username, role, groups.dn as groupname, capability, groups.gid, Attributes.a_name, Role_attrs.a_value "
                                  "FROM usr INNER JOIN ca ON usr.ca=ca.cid "
                                  "INNER JOIN m ON ") + (compat_flag ? "usr.uid = m.uid" : "usr.userid = m.userid ") +
    "INNER JOIN groups ON m.gid=groups.gid "
    "LEFT JOIN roles ON roles.rid = m.rid "
    "LEFT JOIN capabilities ON capabilities.cid = m.cid "
    "INNER JOIN Role_attrs on groups.gid = Role_attrs.g_id "
    "INNER JOIN Attributes on Attributes.a_id = Role_attrs.a_id "
    "WHERE Role_attrs.r_id = roles.rid AND "   
    "ca.ca = \'" + ca + "\' AND "
    "usr.dn = \'" + dn + "\'";
  
  // execute query
  return get_attributes_real(dn, ca, dbname, username, contactstring, port, socket, password, query, result);
}

bool
get_group_and_role_attributes(const std::string &dn, const std::string &ca,
                              const char *group,
                              const std::string &dbname, const std::string &username, const std::string &contactstring,
                              int port, const std::string& socket, const char *password,
                              std::vector<gattrib> &result)
{
  if (dn.empty() || ca.empty() || !group || dbname.empty() || username.empty() || !password)
    return false;
  
  // separate group and role in group:role syntax
  
  char *role;
  char *argument = strdup(group);
  
  if (!argument || !(role = strchr(argument, ':')))
    return false;

  *role++ = '\0';

  if (!acceptable(argument) || !acceptable(role))
    return false;

  // compose query

  std::string query = std::string("SELECT usr.dn as username, role, groups.dn as groupname, capability, groups.gid, Attributes.a_name, Role_attrs.a_value "
                                  "FROM usr INNER JOIN ca ON usr.ca=ca.cid "
                                  "INNER JOIN m ON ") + (compat_flag ? "usr.uid = m.uid" : "usr.userid = m.userid ") +
    "INNER JOIN groups ON m.gid=groups.gid "
    "LEFT JOIN roles ON roles.rid = m.rid "
    "LEFT JOIN capabilities ON capabilities.cid = m.cid "
    "INNER JOIN Role_attrs on groups.gid = Role_attrs.g_id "
    "INNER JOIN Attributes on Attributes.a_id = Role_attrs.a_id "
    "WHERE Role_attrs.r_id = roles.rid AND "  
    "roles.role = \'" + role + "\' AND "
    "groups.dn = \'" + argument + "\' AND "
    "ca.ca = \'" + ca + "\' AND "
    "usr.dn = \'" + dn + "\'";
                                  
  free(argument);

  // execute query
  return get_attributes_real(dn, ca, dbname, username, contactstring, port, socket, password, query, result);
}

bool
get_user_attributes(const std::string &dn, const std::string &ca, 
                    const char *group, 
                    const std::string &dbname, const std::string &username, const std::string &contactstring, 
                    int port, const std::string& socket, const char *password, 
                    std::vector<gattrib> &result)
{
  if (dn.empty() || ca.empty() || !group || dbname.empty() || username.empty() || !password)
    return false;

  // compose query
  
  std::string query = std::string("SELECT usr.dn, ca.ca, Attributes.a_name, Usr_attrs.a_value "
                                  "FROM usr "
                                  "LEFT JOIN ca on usr.ca = ca.cid "
                                  "LEFT JOIN Usr_attrs on usr.userid = Usr_attrs.u_id "
                                  "LEFT JOIN Attributes on Attributes.a_id = Usr_attrs.a_id "
                                  "WHERE "
                                  "ca.ca = \'" + ca + "\' AND "
                                  "usr.dn = \'" + dn + "\'");
  
  return get_attributes_real(dn, ca, dbname, username, contactstring, port, socket, password, query, result);
}

static bool
get_attributes_real(const std::string &dn, const std::string &ca,
                    const std::string &dbname, const std::string &username,
                    const std::string &contactstring, 
                    int port, const std::string& socket,const char *password,
                    const std::string &query,	std::vector<gattrib> &results)
{
  if (dbname.empty() || username.empty() || !password || query.empty())
    return false;
  
  std::string user_additional = std::string("SELECT usr.dn, ca.ca, Attributes.a_name, Usr_attrs.a_value "
                                            "FROM usr "
                                            "LEFT JOIN ca on usr.ca = ca.cid "
                                            "LEFT JOIN Usr_attrs on usr.userid = Usr_attrs.u_id "
                                            "LEFT JOIN Attributes on Attributes.a_id = Usr_attrs.a_id "
                                            "WHERE "
                                            "ca.ca = \'" + ca + "\' AND "
                                            "usr.dn = \'" + dn + "\'");

  std::string additional = std::string("SELECT usr.dn as username, role, groups.dn as groupname, capability, groups.gid, Attributes.a_name, Group_attrs.a_value "
                                       "FROM usr INNER JOIN ca ON usr.ca=ca.cid "
                                       "INNER JOIN m ON ") + (compat_flag ? "usr.uid = m.uid" : "usr.userid = m.userid ") +
                                       "INNER JOIN groups ON m.gid=groups.gid "
                                       "left join roles on roles.rid = m.rid "
                                       "left join capabilities on capabilities.cid = m.cid "
                                       "INNER JOIN Group_attrs on groups.gid = Group_attrs.g_id "
                                       "INNER JOIN Attributes on Attributes.a_id = Group_attrs.a_id "
    "WHERE groups.must IS NOT NULL AND "
    "ca.ca = \'" + ca + "\' AND "
    "usr.dn = \'" + dn + "\' AND "
    "m.rid is NULL";
  
  try
  {
    std::auto_ptr<sqliface::interface> db(NewDB());
    if(connect_with_port_and_socket)
      connect_with_port_and_socket(db.get(), dbname.c_str(), contactstring.c_str(), username.c_str(), port, (!socket.empty() ? socket.c_str() : NULL), password);
    else 
      db->connect(dbname.c_str(), contactstring.c_str(), username.c_str(), password);

    std::auto_ptr<sqliface::query> q(db->newquery());

    *q << "SET TRANSACTION ISOLATION LEVEL SERIALIZABLE";
    q->exec();

    datahash map;

    LOGM(VARP, logh, LEV_DEBUG, T_REQUEST, "ORIGINAL: %s", query.c_str());
    bool ok = get_attributes_real0(db.get(), dn, ca, query, results, map);
    
    LOGM(VARP, logh, LEV_DEBUG, T_REQUEST, "GROUPS: %s", additional.c_str());
    bool ok2 = get_attributes_real0(db.get(), dn, ca, additional, results, map);

    LOGM(VARP, logh, LEV_DEBUG, T_REQUEST, "USER: %s", additional.c_str());
    bool ok3 = get_attributes_real0(db.get(), dn, ca, user_additional, results, map);
    
    *q << "ROLLBACK";
    q->exec();
    
    return ok && ok2 && ok3;
  }
  CATCH

  return false;
}

static bool
get_attributes_real0(sqliface::interface *db, const std::string &dn,
                     const std::string &ca, const std::string &query,
                     std::vector<gattrib> &results, datahash &map)
{
  std::string res;

  if (query.empty())
    return false;

  try 
  {
    std::auto_ptr<sqliface::query> q(db->newquery());

    LOGM(VARP, logh, LEV_DEBUG, T_REQUEST, "QUERY: %s", query.c_str());

    *q << query.c_str();

    std::auto_ptr<sqliface::results> r(q->result());
    
    // parse result set

    while (r->valid())
    {
      gattrib rec;

      rec.name = r->get("A_NAME");
      rec.value  = r->get("A_VALUE");

      try
      {
        rec.qualifier = r->get("GROUPNAME");
        std::string tmp = rec.qualifier;
        try
        {
          std::string tmp = r->get("ROLE");
          if(tmp != "NULL")
            rec.qualifier += "/Role=" + tmp;
        }
        catch(sqliface::DBEXC& e)
        {
          rec.qualifier = tmp;
        }
      }    
      catch(sqliface::DBEXC& e)
      {
        if(e.what() == "Unknown column GROUPNAME.")
          rec.qualifier = "";
      }
      catch(...) {
        LOGM(VARP, logh, LEV_DEBUG, T_REQUEST, "UNKNOWN EXCEPTION: %s", ".");
      }
      results.push_back(rec);

      (void)r->next();
    }
  
    return true;
  }
  CATCH


  LOGM(VARP, logh, LEV_DEBUG, T_REQUEST, "RETURNING: %s", "false");        

  return false;
}

bool get_correct_dn(const std::string &dbname, const std::string &username, 
                    const char *password, const std::string &contactstring, 
                    int port, const std::string &socket, const std::string &name)
{
  if (dbname.empty() || username.empty() || !password || !acceptable(name.c_str()))
    return false;

  bool res = false;

  try {
    std::auto_ptr<sqliface::interface> db(NewDB());
    if(connect_with_port_and_socket)
      connect_with_port_and_socket(db.get(), dbname.c_str(), contactstring.c_str(), username.c_str(), port, (!socket.empty() ? socket.c_str() : NULL), password);
    else 
      db->connect(dbname.c_str(), contactstring.c_str(), username.c_str(), password);

    std::auto_ptr<sqliface::query> q(db->newquery());
    std::string query = "SELECT dn from usr where dn = \"" + name +"\"";
    *q << query.c_str();

    std::auto_ptr<sqliface::results> r(q->result());

    while (r->valid()) {
      (void)r->next();
      res = true;
    }
  }
  CATCH

    return res;
}

bool get_correct_ca(const std::string &dbname, const std::string &username, 
                    const char *password, const std::string &contactstring,
                    int port, const std::string& socket, const std::string &name)
{
  if (dbname.empty() || username.empty() || !password || !acceptable(name.c_str()))
    return false;

  bool res = false;

  try {
    std::auto_ptr<sqliface::interface> db(NewDB());
    if(connect_with_port_and_socket)
      connect_with_port_and_socket(db.get(), dbname.c_str(), contactstring.c_str(), username.c_str(), port, (!socket.empty() ? socket.c_str() : NULL), password);
    else 
      db->connect(dbname.c_str(), contactstring.c_str(), username.c_str(), password);

    std::auto_ptr<sqliface::query> q(db->newquery());
    std::string query = "SELECT cid from ca where ca.ca = \"" + name +"\"";
    *q << query.c_str();

    std::auto_ptr<sqliface::results> r(q->result());

    while (r->valid()) {
      (void)r->next();
      res = true;
    }
  }
  CATCH

    return res;
}
