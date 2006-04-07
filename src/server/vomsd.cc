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

extern "C" {
#include "replace.h"

#define SUBPACKAGE "voms"

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <signal.h>
#include <dlfcn.h>

#include <openssl/evp.h>
#include "newformat.h"
#include "init.h"
#include "gssapi.h"
#include "credentials.h"

#include "log.h"
#include "streamers.h"

static int reload = 0;

void *logh = NULL;
}


#include "Server.h"

#include "VOMSServer.h"

#include "options.h"
#include "data.h"
#include "pass.h"
#include "errors.h"
#include "vomsxml.h"

#include "access_db_sql.h"

#include <map>
#include <set>
#include <string>
#include <algorithm>
#include <iostream>

#include "attribute.h"
#include "dbwrap.h"

#include "voms_api.h"

#ifdef HAVE_GLOBUS_MODULE_ACTIVATE
#include <globus_module.h>
#include <globus_openssl.h>
#endif

extern int AC_Init(void);

#include "ccwrite.h"

extern "C" {
  extern char *get_error(int);
}

static const int DEFAULT_PORT    = 15000;
static const int DEFAULT_TIMEOUT = 60;


typedef std::map<attrib, int> ordermap;

static ordermap ordering;

static std::string firstgroup="";
static std::string firstrole="";

static std::string sqllib = "";

typedef sqliface::interface* (*cdb)();
typedef void (*c)(sqliface::interface *, const char *, const char *, const char *, int, const char *, const char *);

cdb NewDB;
c   connect_with_port_and_socket;

bool compat_flag = false;

static void
sigchld_handler(int sig)
{
  int save_errno = errno;
  pid_t pid;
  int status;

  while ((pid = waitpid(-1, &status, WNOHANG)) > 0 ||
         (pid < 0 && errno == EINTR))
    ;

  signal(SIGCHLD, sigchld_handler);
  errno = save_errno;
}

static void
sighup_handler(int sig)
{
  reload = 1;
}

static bool compare(const attrib &lhs, const attrib &rhs)
{
  ordermap::iterator lhi=ordering.find(lhs);
  ordermap::iterator rhi=ordering.find(rhs);

  LOGM(VARP, logh, LEV_DEBUG, T_PRE, "Comparing: %s:%s to %s:%s",lhs.group.c_str(), lhs.role.c_str(), rhs.group.c_str(), rhs.role.c_str());
  if (lhi == ordering.end()) {
    LOG(logh, LEV_DEBUG, T_PRE, "No left hand side");
    return false;
  }
  if (rhi == ordering.end()) {
    LOG(logh, LEV_DEBUG, T_PRE, "No Right hand side");
    return true;
  }
  LOGM(VARP, logh, LEV_DEBUG, T_PRE, "%d:%d",lhi->second, rhi->second);
  return (lhi->second < rhi->second);
}

static void orderattribs(std::vector<attrib> &v)
{
  std::partial_sort(v.begin(), v.begin()+ordering.size(), v.end(), compare);
}

static void parse_order(const std::string &message, ordermap &ordering)
{
  int order = 0;
  std::string::size_type position = 0;
  bool init = true;

  LOGM(VARP, logh, LEV_DEBUG, T_PRE, "Initiating parse order: %s",message.c_str());
  while (position != std::string::npos) {
    LOG(logh, LEV_DEBUG, T_PRE, "Entered loop");

    if (init) {
      position = 0;
      init = false;
    }
    else
      position++;

    /* There is a specified ordering */
    std::string::size_type end_token = message.find_first_of(',', position);
    std::string attribute;
    if (end_token == std::string::npos)
      attribute = message.substr(position);
    else
      attribute = message.substr(position, end_token - position);
    LOGM(VARP, logh, LEV_DEBUG, T_PRE, "Attrib: %s",attribute.c_str());
    std::string::size_type divider = attribute.find(':');
    attrib temp;
    if (divider == std::string::npos) {
      if (firstgroup.empty()) {
        firstgroup = attribute;
        firstrole = "NULL";
      }
      temp.group = attribute;
      temp.role = "NULL";
    }
    else {
      if (firstgroup.empty()) {
        firstgroup = attribute.substr(0, divider);
        firstrole = attribute.substr(divider+1);
      }
      temp.group = attribute.substr(0, divider);
      temp.role  = attribute.substr(divider+1);
    }
    temp.cap = "";
    LOGM(VARP, logh, LEV_DEBUG, T_PRE, "Order: %s:%s",temp.group.c_str(),temp.role.c_str());
    ordering.insert(std::make_pair<attrib, int>(temp,order));
    order++;
    position = end_token;
  }
}

static void parse_targets(const std::string &message,
                          std::vector<std::string> &target)
{
  std::string::size_type position = 0;

  bool init = true;

  while (position != std::string::npos) {
    if (!init)
      position++;
    else
      init = false;

    /* There is a specified ordering */
    std::string::size_type end_token = message.find_first_of(',',position);
    std::string attribute;
    if (end_token == std::string::npos)
      attribute = message.substr(position);
    else
      attribute = message.substr(position, end_token - position);
    target.push_back(attribute);
    position = end_token;
  }
}

bool not_in(std::string fqan, std::vector<std::string> fqans)
{
  return (find(fqans.begin(), fqans.end(), fqan) == fqans.end());
}

VOMSServer::VOMSServer(int argc, char *argv[]) : sock(0,0,NULL,50,false),
                                                 validity(86400),
                                                 logfile("/var/log/voms"),
                                                 gatekeeper_test(false),
                                                 daemon_port(DEFAULT_PORT),
                                                 foreground(false),
                                                 globuspwd(""), globusid(""),
                                                 x509_cert_dir(""),
                                                 x509_cert_file(""),
                                                 x509_user_proxy(""),
                                                 x509_user_cert(""),
                                                 x509_user_key(""),
                                                 desired_name_char(""),
                                                 username("voms"),
                                                 dbname("voms"),
                                                 contactstring(""),
                                                 mysql_port(0),
                                                 mysql_socket(""),
                                                 passfile(""),
                                                 voname("unspecified"),
                                                 uri(""), version(0),
                                                 subject(""), ca(""),
                                                 debug(false), code(-1),
                                                 backlog(50), logger(NULL),
                                                 socktimeout(-1),
                                                 logmax(10000000),loglev(2),
                                                 logt(T_STARTUP|T_REQUEST|T_RESULT), 
                                                 logdf("%c"),
                                                 logf("%d:%h:%s(%p):%V:%T:%F (%f:%l):%m"),
                                                 newformat(false)
{
  struct stat statbuf;

  signal(SIGCHLD, sigchld_handler);
  ac = argc;
  av = argv;

  if ((stat("/etc/nologin", &statbuf)) == 0)
    throw VOMSInitException("/etc/nologin present\n");

#ifdef HAVE_GLOBUS_MODULE_ACTIVATE
  if (globus_module_activate(GLOBUS_GSI_GSS_ASSIST_MODULE) != GLOBUS_SUCCESS ||
      globus_module_activate(GLOBUS_OPENSSL_MODULE) != GLOBUS_SUCCESS)
    throw VOMSInitException("Cannot initializa Globus\n");
#endif

  std::string fakeuri = "";
  bool progversion = false;

  struct option opts[] = {
    {"help",            0, NULL,                      OPT_HELP},
    {"usage",           0, NULL,                      OPT_HELP},
    {"test",            0, (int *)&gatekeeper_test,   OPT_BOOL},
    {"conf",            1, NULL,                      OPT_CONFIG},
    {"port",            1, &daemon_port,              OPT_NUM},
    {"logfile",         1, (int *)&logfile,           OPT_STRING},
    {"globusid",        1, (int *)&globusid,          OPT_STRING},
    {"globuspwd",       1, (int *)&globuspwd,         OPT_STRING},
    {"x509_cert_dir",   1, (int *)&x509_cert_dir,     OPT_STRING},
    {"x509_cert_file",  1, (int *)&x509_cert_file,    OPT_STRING},
    {"x509_user_proxy", 1, (int *)&x509_user_proxy,   OPT_STRING},
    {"x509_user_cert",  1, (int *)&x509_user_cert,    OPT_STRING},
    {"x509_user_key",   1, (int *)&x509_user_key,     OPT_STRING},
    {"desired_name",    1, (int *)&desired_name_char, OPT_STRING},
    {"foreground",      0, (int *)&foreground,        OPT_BOOL},
    {"username",        1, (int *)&username,          OPT_STRING},
    {"timeout",         1, &validity,                 OPT_NUM},
    {"dbname",          1, (int *)&dbname,            OPT_STRING},
    {"contactstring",   1, (int *)&contactstring,    OPT_STRING},
    {"mysql-port",       1, (int *)&mysql_port,         OPT_NUM},
    {"mysql-socket",     1, (int *)&mysql_socket,       OPT_STRING},
    {"passfile",        1, (int *)&passfile,          OPT_STRING},
    {"vo",              1, (int *)&voname,            OPT_STRING},
    {"uri",             1, (int *)&fakeuri,           OPT_STRING},
    {"globus",          1, &version,                  OPT_NUM},
    {"version",         0, (int *)&progversion,       OPT_BOOL},
    {"backlog",         1, &backlog,                  OPT_NUM},
    {"debug",           0, (int *)&debug,             OPT_BOOL},
    {"code",            1, &code,                     OPT_NUM},
    {"loglevel",        1, &loglev,                   OPT_NUM},
    {"logtype",         1, &logt,                     OPT_NUM},
    {"logformat",       1, (int *)&logf,              OPT_STRING},
    {"logdateformat",   1, (int *)&logdf,             OPT_STRING},
    {"sqlloc",          1, (int *)&sqllib,            OPT_STRING},
    {"compat",          1, (int *)&compat_flag,       OPT_BOOL},
    {"socktimeout",     1, &socktimeout,              OPT_NUM},
    {"logmax",          1, &logmax,                   OPT_NUM},
    {"newformat",       1, (int *)&newformat,         OPT_BOOL},
    {0, 0, 0, 0}
  };

  /*
   * Parse the command line arguments
   */

  set_usage("[-help] [-usage] [-conf parmfile] [-foreground] [-port port]\n"
            "[-logfile file] [-passfile file] [-vo voname]\n"
            "[-globusid globusid] [-globuspwd file] [-globus version]\n"
            "[-x509_cert_dir path] [-x509_cert_file file]\n"
            "[-x509_user_cert file] [-x509_user_key file]\n"
            "[-dbname name] [-username name] [-contactstring name]\n"
            "[-mysql-port port] [-mysql-socket socket] [-timeout limit]\n"
            "[-x509_user_proxy file] [-test] [-uri uri] [-code num]\n"
            "[-loglevel lev] [-logtype type] [-logformat format]\n"
            "[-logdateformat format] [-debug] [-backlog num]\n"
            "[-version][--sqlloc path][--compat][--logmax n][--socktimeout n]\n");

  if (!getopts(argc, argv, opts))
    throw VOMSInitException("unable to read options");

  if (socktimeout == -1 && debug)
    socktimeout = 0;
  else
    socktimeout = DEFAULT_TIMEOUT;

  if (code == -1)
    code = daemon_port;

  if (progversion) {
    std::cout << SUBPACKAGE << "\nVersion: " << VERSION << std::endl;
    std::cout << "Compiled: " << __DATE__ << " " << __TIME__ << std::endl;
    exit(0);
  }

  if ((logh = LogInit())) {
    if ((logger = FileNameStreamerAdd(logh, logfile.c_str(), logmax, code, 0))) {
      loglevels lev;

      switch(loglev) {
      case 1: lev = LEV_NONE; break;
      case 2: lev = LEV_ERROR; break;
      case 3: lev = LEV_WARN; break;
      case 4: lev = LEV_INFO; break;
      case 5: lev = LEV_DEBUG; break;
      default: lev = LEV_DEBUG; break;
      }
      if (debug)
        lev = LEV_DEBUG;

      if (lev == LEV_DEBUG)
        logt = T_STARTUP|T_REQUEST|T_RESULT;

      (void)LogLevel(logh, lev);
      (void)LogType(logh, logt);
      (void)SetCurLogType(logh, T_STARTUP);
      (void)LogService(logh, "vomsd");
      (void)LogFormat(logh, logf.c_str());
      (void)LogDateFormat(logh, logdf.c_str());
    }
  }
  else
    throw VOMSInitException("logging startup failure");

  if (debug) {
    LOGM(VARP, logh, LEV_INFO, T_PRE, "Package: %s", SUBPACKAGE);
    LOGM(VARP, logh, LEV_INFO, T_PRE, "Version: %s", VERSION);
    LOGM(VARP, logh, LEV_INFO, T_PRE, "Compiled: %s %s", __DATE__, __TIME__);
    for (int i = 0; i < argc; i++)
      LOGM(VARP, logh, LEV_DEBUG, T_PRE, "argv[%d] = \"%s\"", i, argv[i]);
  }

  if (!sqllib.empty()) {
    void * library = dlopen(sqllib.c_str(), RTLD_LAZY);
    if(!library) {
      LOG(logh, LEV_ERROR, T_PRE, ((std::string)("Cannot load library: " + sqllib)).c_str());
      std::cout << "Cannot load library: "<< sqllib << std::endl;
      std::cout << dlerror() << std::endl;
      exit(1);
    }
    
    NewDB = (cdb)dlsym(library, "CreateDB");
    if (!NewDB) {
      LOG(logh, LEV_ERROR, T_PRE, ((std::string)("Cannot load library: " + sqllib)).c_str());
      std::cout << "Cannot load library: "<< sqllib << dlerror() << std::endl;
      exit(1);
    }

    connect_with_port_and_socket = (c)dlsym(library, "Connect_with_port_and_socket");
    if (!connect_with_port_and_socket && (mysql_port || !mysql_socket.empty())) {
      LOG(logh, LEV_ERROR, T_PRE, "Old version of DBMS interface detected: won't use mysql-port and mysql-socket for MySQL connection (you shouldn't be using them if you're using Oracle).");
    }
  }
  else {
    std::cout << "Cannot load library! "<< std::endl;
    LOG(logh, LEV_ERROR, T_PRE, "Cannot load library!" );
    exit(1);
  }

  if (!getpasswd(passfile, logh))  {
    LOG(logh, LEV_ERROR, T_PRE, "can't read password file!\n");
    throw VOMSInitException("can't read password file!");
  }

  if(contactstring.empty())
    contactstring = (std::string)"localhost";

  int v = get_version(dbname, username, contactstring, mysql_port, mysql_socket, passwd());

  if ((v == 2) || ((v == 1) && compat_flag))
    ;
  else {
    LOGM(VARP, logh, LEV_ERROR, T_PRE, "Detected DB Version: %d. Required DB version >= 2", v);
    throw VOMSInitException("wrong database version");
  }

  version = globus(version);
  if (version == 0) {
    std::cerr << "Unable to discover Globus Version: Trying for 2.2"
              << std::endl;
    LOG(logh, LEV_WARN, T_PRE, "Unable to discover Globus Version: Trying for 2.2");
    version = 22;
  }

  if (fakeuri.empty()) {
    int   ok;

    int   hostnamesize = 50;
    char *hostname = new char[1];
    do {
      delete[] hostname;
      hostname = new char[hostnamesize];
      ok = gethostname(hostname, hostnamesize);
      hostnamesize += 50;
    } while (ok);
    std::string temp;

    uri = std::string(hostname) + ":" + stringify(daemon_port, temp);
    delete[] hostname;
  }
  else
    uri = fakeuri;

  sock = GSISocketServer(daemon_port, version, NULL, backlog);

  setenv("GLOBUSID", globusid.c_str(), 1);

  /*
   * Dont use default env proxy cert for gatekeeper if run as root
   * this might get left over. You can still use -x509_user_proxy
   */

  unsetenv("X509_USER_PROXY");

  if (!globuspwd.empty()) {
    setenv("GLOBUSPWD", globuspwd.c_str(), 1);
  }

  if (!x509_cert_dir.empty()) {
    setenv("X509_CERT_DIR", x509_cert_dir.c_str(), 1);
  }
  if (!x509_cert_file.empty()) {
    setenv("X509_CERT_FILE", x509_cert_file.c_str(), 1);
  }
  if (!x509_user_proxy.empty()) {
    setenv("X509_USER_PROXY", x509_user_proxy.c_str(), 1);
  }
  if (!x509_user_cert.empty()) {
    setenv("X509_USER_CERT", x509_user_cert.c_str(), 1);
  }
  if (!x509_user_key.empty()) {
    setenv("X509_USER_KEY", x509_user_key.c_str(), 1);
  }

  sock.SetFlags(GSS_C_MUTUAL_FLAG | GSS_C_CONF_FLAG | GSS_C_INTEG_FLAG);
  sock.SetLogger(logh);
  std::string msg = "URI: " + uri;

  LOGM(VARP, logh, LEV_INFO, T_PRE, "URI: %s", uri.c_str());
  LOGM(VARP,  logh, LEV_INFO, T_PRE, "Detected Globus Version: %d", version);

  AC_Init();
}

VOMSServer::~VOMSServer() {}

void VOMSServer::Run()
{
  pid_t pid = 0;

  if (!debug)
    if (daemon(0,0))
      exit(0);

  try {
    signal(SIGHUP, sighup_handler);
    LOG(logh, LEV_DEBUG, T_PRE, "Trying to open socket.");
    sock.Open();
    sock.SetTimeout(socktimeout);

    for (;;) {

      if (reload) {
        reload=0;
        UpdateOpts();
      }

      if (sock.Listen()) {
        if (reload) {
          reload=0;
          UpdateOpts();
        }
        (void)SetCurLogType(logh, T_REQUEST);

        if (!gatekeeper_test && !debug) {
          pid = fork();
          if (pid) {
            LOGM(VARP, logh, LEV_INFO, T_PRE, "Starting Executor with pid = %d", pid);
            sock.CloseListened();
          }
        }

        if (!pid) {
          bool value = false;

          if (!debug && !gatekeeper_test)
            sock.CloseListener();
          if (sock.AcceptGSIAuthentication()) {
	
            LOGM(VARP, logh, LEV_INFO, T_PRE, "Self    : %s", sock.own_subject.c_str());
            LOGM(VARP, logh, LEV_INFO, T_PRE, "Self CA : %s", sock.own_ca.c_str());

            std::string user    = sock.peer_subject;
            std::string userca  = sock.peer_ca;
            subject = sock.own_subject;
            ca = sock.own_ca;

            LOGM(VARP, logh, LEV_INFO, T_PRE, "At: %s Received Contact from:", timestamp().c_str());
            LOGM(VARP, logh, LEV_INFO, T_PRE, " user: %s", user.c_str());
            LOGM(VARP, logh, LEV_INFO, T_PRE, " ca  : %s", userca.c_str());	
            LOGM(VARP, logh, LEV_INFO, T_PRE, " serial: %s", sock.peer_serial.c_str());

            LOG(logh, LEV_DEBUG, T_PRE, "Starting Execution.");
            value = Execute(user, userca, sock.own_key, sock.own_cert, sock.peer_cert, sock.GetContext());
          }
          else {
            LOGM(VARP, logh, LEV_INFO, T_PRE, "Failed to authenticate peer");	
            sock.CleanSocket();
          }

          if (!debug && !gatekeeper_test) {
            sock.Close();
            exit(value == false ? 1 : 0);
          }
          else {
            sock.CloseListened();
          }
        }
      }
      else {
        LOGM(VARP, logh, LEV_ERROR, T_PRE, "Cannot listen on port %d", daemon_port);
        exit(1);
      }
    }
  }
  catch (...) {}
}

static std::string translate(const std::string& name)
{
  std::string::size_type userid = name.find(std::string("/USERID="));
  std::string::size_type uid = name.find(std::string("/UID="));

  if (userid != std::string::npos)
    return name.substr(0, userid) + "/UID=" + name.substr(userid+8);
  else if (uid != std::string::npos)
    return name.substr(0, uid) + "/USERID=" + name.substr(uid+5);
  else
    return name;
} 

bool
VOMSServer::Execute(const std::string &client_name, const std::string &ca_name,
                    EVP_PKEY *key, X509 *issuer, X509 *holder, gss_ctx_id_t context)
{
  std::string message;
  std::string client = client_name;
  std::string newname = translate(client);

  if (!sock.Receive(message)) {
    LOG(logh, LEV_ERROR, T_PRE, "Unable to receive request.");
    sock.CleanSocket();
    return false;
  }

  LOGM(VARP, logh, LEV_DEBUG, T_PRE, "Received Request: %s", message.c_str());

  struct request r;

  if (!XML_Req_Decode(message, r)) {
    LOGM(VARP, logh, LEV_ERROR, T_PRE, "Unable to interpret command: %s",message.c_str());
    return false;
  }
  
  std::vector<std::string> comm = r.command;
  
  int requested = r.lifetime;

  std::vector<std::string> targs;

  firstgroup = firstrole = "";
  ordering.clear();

  parse_order(r.order, ordering);
  parse_targets(r.targets, targs);

  std::vector<attrib> res;
  std::string data = "";
  std::string tmp="";
  bool result = true;
  std::vector<errorp> errs;
  errorp err;

  /* Interpret user requests */

  if (requested != 0) {
    if (validity < requested) {
      err.num = WARN_SHORT_VALIDITY;
      err.message = uri + ": validity shortened to " +
        stringify(validity, tmp) + " seconds!";
      errs.push_back(err);
      requested = validity;
    }
  }

  std::string command;
  for(std::vector<std::string>::iterator i = comm.begin(); i < comm.end(); ++i)
  {
    command = *i;
    
    LOGM(VARP, logh, LEV_INFO, T_PRE, "Next command : %s", i->c_str());
    
    /* Interpret request by first character */
    switch (*(i->c_str()))
    {
    case 'A':
      result &=
        get_all(client, ca_name, dbname, username, contactstring, mysql_port, mysql_socket, passwd(), res);
      if (!result && (newname != client))
        result=
          get_all(newname, ca_name, dbname, username, contactstring, mysql_port, mysql_socket, passwd(), res);
      break;

    case 'R':
      result &=
        get_role(client, ca_name, i->c_str() + 1, dbname, username, contactstring, mysql_port, mysql_socket, passwd(), res);
      if (!result && (newname != client))
        result=
          get_role(newname, ca_name, i->c_str() + 1, dbname, username, contactstring, mysql_port, mysql_socket, passwd(), res);
      
      break;
	
    case 'G':
      result &=
        get_group(client, ca_name, i->c_str() + 1, dbname, username, contactstring, mysql_port, mysql_socket, passwd(), res);
      if (!result && (newname != client))
        result=
          get_group(newname, ca_name, i->c_str() + 1, dbname, username, contactstring, mysql_port, mysql_socket, passwd(), res);
      break;

    case 'B':
      result &=
        get_group_and_role(client_name, ca_name, i->c_str() + 1, dbname, username, contactstring, mysql_port, mysql_socket, passwd(), res);
      if (!result && (newname != client))
        result=
          get_group_and_role(newname, ca_name, i->c_str() + 1, dbname, username, contactstring, mysql_port, mysql_socket, passwd(), res);
      
      break;

    case 'S':
      result &=
        special(client_name, ca_name, i->c_str() + 1, dbname, username, contactstring, mysql_port, mysql_socket, passwd(), data);
      if (!result && (newname != client))
        result=
          special(newname, ca_name, i->c_str() + 1, dbname, username, contactstring, mysql_port, mysql_socket, passwd(), data);
      break;

    case 'L':
      result &=
        listspecial(dbname, username, contactstring, mysql_port, mysql_socket, passwd(), data);
      break;

    case 'M':
      result &= getlist(client_name, ca_name, dbname, username, contactstring, mysql_port, mysql_socket, passwd(), data);
      if (!result && (newname != client))
        result=
          getlist(newname, ca_name, dbname, username, contactstring, mysql_port, mysql_socket, passwd(), data);
      break;

    case 'N':
      result &=
        get_all(client, ca_name, dbname, username, contactstring, mysql_port, mysql_socket, passwd(), res);
      if (!result && (newname != client))
        result=
          get_all(newname, ca_name, dbname, username, contactstring, mysql_port, mysql_socket, passwd(), res);
      break;

    default:
      result &= false;
      LOGM(VARP, logh, LEV_ERROR, T_PRE, "Unknown Command \"%c\"", i->c_str());
      break;
    } 
    
    if(!result)
      break;
  } 
  
  // remove duplicates
  for(std::vector<attrib>::iterator i = res.begin(); i != res.end(); ++i)
  {
    res.erase(std::remove(i+1, res.end(), *i),
              res.end());
  }

  if(result && !res.empty())
  {
    orderattribs(res);
  }

  if (!result) 
  {
    LOG(logh, LEV_ERROR, T_PRE, "Error in executing request!");
    err.num = ERR_NOT_MEMBER;
    if (command == (std::string("G/")+ voname))
      err.message = voname + ": User unknown to this VO.";
    else
      err.message = voname + ": Unable to satisfy " + command + " Request!";
    errs.push_back(err);
    std::string ret = XML_Ans_Encode("A", errs);
    LOGM(VARP, logh, LEV_DEBUG, T_PRE, "Sending: %s", ret.c_str());
    sock.Send(ret);
    return false;
  }

  std::vector<std::string> compact;
  int j = 0;

  for (std::vector<attrib>::iterator i = res.begin(); i != res.end(); i++) 
  {
    compact.push_back(i->str());
    j++;
  }
  
  /* check the user is allowed to requests those attributes */

  vomsdata v("", "");
  v.SetVerificationType((verify_type)(VERIFY_SIGN));
  v.RetrieveFromCtx(context, RECURSE_DEEP);
  
  /* find the attributes corresponding to the vo */

  std::vector<std::string> fqans;
  for(std::vector<voms>::iterator index = (v.data).begin(); index != (v.data).end(); ++index)
  {
    if(index->voname == voname)
      fqans.insert(fqans.end(), 
                   index->fqan.begin(), 
                   index->fqan.end());
  }

  /* if attributes were found, only release an intersection beetween the requested and the owned */

  std::vector<std::string>::iterator end = compact.end();
  bool subset = false;
  if(!fqans.empty())
    if((compact.erase(remove_if(compact.begin(),
                                compact.end(), 
                                bind2nd(std::ptr_fun(not_in), fqans)), 
                      compact.end()) != end))
      subset = true;
  
  if (compact.empty()) {
    LOG(logh, LEV_ERROR, T_PRE, "Error in executing request!");
    err.num = ERR_ATTR_EMPTY;
    err.message = voname + " : your certificate already contains attributes, only a subset of them can be issued.";
    errs.push_back(err);
    std::string ret = XML_Ans_Encode("A", errs);
    LOGM(VARP, logh, LEV_DEBUG, T_PRE, "Sending: %s", ret.c_str());
    sock.Send(ret);
    return false;
  }

  if(subset)
  {
    LOG(logh, LEV_ERROR, T_PRE, "Error in executing request!");
    err.num = WARN_ATTR_SUBSET;
    err.message = voname + " : your certificate already contains attributes, only a subset of them can be issued.";
    errs.push_back(err);
  }
  
  if (j) {
    if (!firstgroup.empty()) {
      std::vector<attrib>::iterator i = res.begin();
      if (i != res.end()) {
        LOGM(VARP, logh, LEV_DEBUG, T_PRE,  "fg:fr = %s:%s", firstgroup.c_str(), firstrole.c_str());
        if ((i->group != firstgroup) || (i->role != firstrole)) {
          err.num = WARN_NO_FIRST_SELECT;
          err.message = "GROUP: " + i->group + "\nROLE: " + i->role + " is not the first selected!\n";
          errs.push_back(err);
        }
      }
    }

    BIGNUM * serial = get_serial(code, dbname, username, contactstring, mysql_port, mysql_socket, passwd());

    int res = 1;
    std::string codedac;

    if (comm.at(0) != "N")
    {
      if (!serial)
        LOG(logh, LEV_ERROR, T_PRE, "Can't get Serial Number!");
      
      if (serial) {
        AC *a = AC_new();

        LOGM(VARP, logh, LEV_DEBUG, T_PRE, "length = %d", i2d_AC(a, NULL));
        if (a)
          res = createac(issuer, sock.own_stack, holder, key, serial, compact, targs, &a,
                         voname, uri, requested, !newformat);

        LOGM(VARP, logh, LEV_DEBUG, T_PRE, "length = %d", i2d_AC(a, NULL));
        BN_free(serial);

        if (!res) {
          unsigned int len = i2d_AC(a, NULL);

          unsigned char *tmp = (unsigned char *)OPENSSL_malloc(len);
          unsigned char *ttmp = tmp;

          LOGM(VARP, logh, LEV_DEBUG, T_PRE, "length = %d", len);

          if (tmp) {
            i2d_AC(a, &tmp);
            codedac = std::string((char *)ttmp, len);
          }
        }
        else {
          err.num = ERR_NOT_MEMBER;
          err.message = std::string(get_error(res));
          errs.push_back(err);
        }
      }
      
      if (res || codedac.empty()) {
        LOG(logh, LEV_ERROR, T_PRE, "Error in executing request!");
        err.message = voname + ": Unable to satisfy " + command + " request due to database error.";
        errs.push_back(err);
        std::string ret = XML_Ans_Encode("A", errs);
        LOGM(VARP, logh, LEV_DEBUG, T_PRE, "Sending: %s", ret.c_str());
        sock.Send(ret);
        return false;
      }
    }

    (void)SetCurLogType(logh, T_RESULT);

    if (comm[0] == "N")
      data = "";

    for (std::vector<std::string>::iterator i = compact.begin(); i != compact.end(); i++) {
      LOGM(VARP, logh, LEV_INFO, T_PRE, "Request Result: %s",  (*i).c_str());
      if (comm.at(0) == "N")
        data += (*i).c_str() + std::string("\n");
    }

    std::string ret = XML_Ans_Encode(codedac, data, errs);

    LOGM(VARP, logh, LEV_DEBUG, T_PRE, "OUTPUT: %s", ret.c_str());
    sock.Send(ret);
  }
  else if (!data.empty()) {
    std::string ret = XML_Ans_Encode("", data, errs);
    LOGM(VARP, logh, LEV_DEBUG, T_PRE, "OUTPUT: %s", ret.c_str());
    sock.Send(ret);
  }
  else {
    err.num = ERR_NOT_MEMBER;
    err.message = std::string("You are not a member of the ") + voname + " VO!";
    errs.push_back(err);
    std::string ret = XML_Ans_Encode("", errs);
    sock.Send(ret);
  }
  return true;
}

void VOMSServer::UpdateOpts(void)
{
  std::string nlogfile = logfile;
  std::string fakeuri = "";
  int nblog = 50;
  bool progversion = false;
  int nport;

  struct option opts[] = {
    {"test",            0, (int *)&gatekeeper_test,   OPT_BOOL},
    {"conf",            1, NULL,                      OPT_CONFIG},
    {"port",            1, &nport,                    OPT_NUM},
    {"logfile",         1, (int *)&nlogfile,          OPT_STRING},
    {"globusid",        1, (int *)&globusid,          OPT_STRING},
    {"globuspwd",       1, (int *)&globuspwd,         OPT_STRING},
    {"x509_cert_dir",   1, (int *)&x509_cert_dir,     OPT_STRING},
    {"x509_cert_file",  1, (int *)&x509_cert_file,    OPT_STRING},
    {"x509_user_proxy", 1, (int *)&x509_user_proxy,   OPT_STRING},
    {"x509_user_cert",  1, (int *)&x509_user_cert,    OPT_STRING},
    {"x509_user_key",   1, (int *)&x509_user_key,     OPT_STRING},
    {"desired_name",    1, (int *)&desired_name_char, OPT_STRING},
    {"foreground",      0, (int *)&foreground,        OPT_BOOL},
    {"username",        1, (int *)&username,          OPT_STRING},
    {"timeout",         1, &validity,                 OPT_NUM},
    {"dbname",          1, (int *)&dbname,            OPT_STRING},
    {"contactstring",   1, (int *)&contactstring,     OPT_STRING},
    {"mysql-port",       1, (int *)&mysql_port,         OPT_NUM},
    {"mysql-socket",     1, (int *)&mysql_socket,       OPT_STRING},
    {"passfile",        1, (int *)&passfile,          OPT_STRING},
    {"vo",              1, (int *)&voname,            OPT_STRING},
    {"uri",             1, (int *)&fakeuri,           OPT_STRING},
    {"globus",          1, &version,                  OPT_NUM},
    {"version",         0, (int *)&progversion,       OPT_BOOL},
    {"backlog",         1, &nblog,                    OPT_NUM},
    {"debug",           0, (int *)&debug,             OPT_BOOL},
    {"code",            1, &code,                     OPT_NUM},
    {"loglevel",        1, &loglev,                   OPT_NUM},
    {"logtype",         1, &logt,                     OPT_NUM},
    {"logformat",       1, (int *)&logf,              OPT_STRING},
    {"logdateformat",   1, (int *)&logdf,             OPT_STRING},
    {"sqlloc",          1, (int *)&sqllib,            OPT_STRING},
    {"compat",          1, (int *)&compat_flag,       OPT_BOOL},
    {"socktimeout",     1, &socktimeout,              OPT_NUM},
    {"logmax",          1, &logmax,                   OPT_NUM},
    {"newformat",       1, (int *)&newformat,         OPT_BOOL},
    {0, 0, 0, 0}
  };

  (void)SetCurLogType(logh, T_STARTUP);

  if (!getopts(ac, av, opts)) {
    LOG(logh, LEV_ERROR, T_PRE, "Unable to read options!");
    throw VOMSInitException("unable to read options");
  }

  if (nlogfile != logfile) {
    LOGM(VARP, logh, LEV_INFO, T_PRE, "Redirecting logs to: %s", logfile.c_str());

    void *logger2 = FileNameStreamerAdd(logh, nlogfile.c_str(), logmax, code, 1);

    if (!logger2)
      LOG(logh, LEV_WARN, T_PRE, "Logging redirection failure");
    else {
      (void)FileNameStreamerRem(logh, logger);
      logger = logger2;
      logfile = nlogfile;
    }
    sock.SetFlags(GSS_C_MUTUAL_FLAG | GSS_C_CONF_FLAG | GSS_C_INTEG_FLAG);
    sock.SetLogger(logh);
  }

  if (logh) {
    loglevels lev;

    switch(loglev) {
    case 1: lev = LEV_NONE; break;
    case 2: lev = LEV_ERROR; break;
    case 3: lev = LEV_WARN; break;
    case 4: lev = LEV_INFO; break;
    case 5: lev = LEV_DEBUG; break;
    default: lev = LEV_DEBUG; break;
    }
    if (debug)
      lev = LEV_DEBUG;
    (void)LogLevel(logh, lev);

    if (lev == LEV_DEBUG)
      logt = T_STARTUP|T_REQUEST|T_RESULT;


    (void)LogType(logh, logt);
    (void)SetCurLogType(logh, T_STARTUP);
    (void)LogService(logh, "vomsd");
    (void)LogFormat(logh, logf.c_str());
    (void)LogDateFormat(logh, logdf.c_str());
  }

  if (nport != daemon_port) {
    if (!sock.ReOpen(daemon_port = nport, version, nblog, true))
      LOG(logh, LEV_ERROR, T_PRE, "Failed to reopen socket! Server in unconsistent state.");
  }
  else if (nblog != backlog)
    sock.AdjustBacklog(backlog = nblog);

  if (fakeuri.empty()) {
    int   ok;

    int   hostnamesize = 50;
    char *hostname = new char[1];
    do {
      delete[] hostname;
      hostname = new char[hostnamesize];
      ok = gethostname(hostname, hostnamesize);
      hostnamesize += 50;
    } while (ok);
    std::string temp;

    uri = std::string(hostname) + ":" + stringify(daemon_port, temp);
    delete[] hostname;
  }
  else
    uri = fakeuri;

  setenv("GLOBUSID", globusid.c_str(), 1);

  if (!getpasswd(passfile, logh)){
    throw VOMSInitException("can't read password file!");
  }

  if (!globuspwd.empty()) {
    setenv("GLOBUSPWD", globuspwd.c_str(), 1);
  }

  if (!x509_cert_dir.empty()) {
    setenv("X509_CERT_DIR", x509_cert_dir.c_str(), 1);
  }
  if (!x509_cert_file.empty()) {
    setenv("X509_CERT_FILE", x509_cert_file.c_str(), 1);
  }
  if (!x509_user_proxy.empty()) {
    setenv("X509_USER_PROXY", x509_user_proxy.c_str(), 1);
  }
  if (!x509_user_cert.empty()) {
    setenv("X509_USER_CERT", x509_user_cert.c_str(), 1);
  }
  if (!x509_user_key.empty()) {
    setenv("X509_USER_KEY", x509_user_key.c_str(), 1);
  }

  if (debug)
    LOG(logh, LEV_INFO, T_PRE, "DEBUG MODE ACTIVE ");
  else
    LOG(logh, LEV_INFO, T_PRE, "DEBUG MODE INACTIVE ");
}
