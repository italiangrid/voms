/*********************************************************************
 *
 * Authors: Vincenzo Ciaschini - Vincenzo.Ciaschini@cnaf.infn.it
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
#include "config.h"

extern "C" {
#include "replace.h"
#include "uuid.h"
#include "doio.h"

#define SUBPACKAGE "voms"

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <signal.h>
#include <dlfcn.h>
#include <ctype.h>

#include <openssl/evp.h>
#include "newformat.h"
#include "init.h"
#include "credentials.h"

#include "log.h"

#include "sslutils.h"

static int reload = 0;

void *logh = NULL;
#include "myproxycertinfo.h"
}

#include "Server.h"

#include "options.h"
#include "data.h"
#include "pass.h"
#include "errors.h"
#include "vomsxml.h"

#include <map>
#include <set>
#include <string>
#include <algorithm>
#include <iostream>

#include "attribute.h"

#include "dbwrap.h"

#include "voms_api.h"

#include "soapH.h"

extern int AC_Init(void);
extern int http_get(soap *soap);

#include "ccwrite.h"
#include "validate.h"

#include "VOMSServer.h"

std::string vomsresult::makeRESTAnswer(int& code)
{
  std::string output = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><voms>";
  code = SOAP_HTML;

  if (ac != "A" && !ac.empty())
    output += "<ac>"+Encode(ac, true)+"</ac>";

  if (!data.empty())
    output += "<bitstr>"+Encode(data, true)+"</bitstr>";

  std::vector<errorp>::const_iterator end = errs.end();
  for (std::vector<errorp>::const_iterator i = errs.begin(); i != end; ++i) {
    bool warning = i->num < ERROR_OFFSET ? true : false;
    
    std::string strcode;

    switch (i->num) {
    case ERR_SUSPENDED:
      strcode = "SuspendedUser";
      code = 403;
      break;

    case ERR_NOT_MEMBER:
      if (strstr(i->message.c_str(), "Unable to satisfy") == NULL) {
        strcode = "NoSuchUser"; 
        code = 403;
      }
      else {
        strcode = "BadRequest";
        code = 400;
      }
      break;

    case ERR_NO_COMMAND:
      strcode="BadRequest";
      code = 400;
      break;

    default:
      strcode = "InternalError";
      code = 500;
    }

    if (warning)
      output += "<warning>" + i->message + "</warning>";
    else
      output += "<error><code>" + strcode + "</code><message>" + i->message +
        "</message></error>";

    if (code != SOAP_HTML)
      break;
  }
  output += "</voms>";

  return output;
}

SOAP_NMAC struct Namespace namespaces[] =
{
  {NULL, NULL, NULL, NULL}
};

static const int DEFAULT_PORT    = 15000;
static const int DEFAULT_TIMEOUT = 60;

static std::string dummy;

sqliface::interface *db = NULL;

typedef std::map<std::string, int> ordermap;

static ordermap ordering;

static std::string sqllib = "";

char *maingroup = NULL;

typedef sqliface::interface* (*cdb)();
typedef int (*gv)();

cdb NewDB;
gv  getlibversion;

bool dummyb = false;

static bool checkinside(gattrib g, std::vector<std::string> list);
static signed long int get_userid(sqliface::interface *db, X509 *cert, const std::string& voname, vomsresult &vr);
static std::string addtoorder(std::string previous, char *group, char *role);
static bool determine_group_and_role(std::string command, char *comm, char **group, char **role);
static BIGNUM *get_serial();
static void sigchld_handler(UNUSED(int sig));
static void sighup_handler(UNUSED(int sig));
static void sigterm_handler(UNUSED(int sig));
static bool compare(const std::string &lhs, const std::string &rhs);
static void orderattribs(std::vector<std::string> &v);
static std::string parse_order(const std::string &message, ordermap &ordering);
static void parse_targets(const std::string &message, std::vector<std::string> &target);
static bool not_in(std::string fqan, std::vector<std::string> fqans);
static void AdjustURI(std::string &uri, int port);

static void
sigchld_handler(UNUSED(int sig))
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
sighup_handler(UNUSED(int sig))
{
  reload = 1;
}

static void
sigterm_handler(UNUSED(int sig))
{
  exit(0);
}

static bool compare(const std::string &lhs, const std::string &rhs)
{
  ordermap::iterator lhi=ordering.find(lhs);
  ordermap::iterator rhi=ordering.find(rhs);

  LOGM(VARP, logh, LEV_DEBUG, T_PRE, "Comparing: %s to %s", lhs.c_str(), rhs.c_str());
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

static void orderattribs(std::vector<std::string> &v)
{
  int sortsize = (ordering.size() < v.size() ? ordering.size() : v.size());

  std::partial_sort(v.begin(), v.begin() + sortsize, v.end(), compare);
}

static std::string parse_order(const std::string &message, ordermap &ordering)
{
  int order = 0;
  std::string first;

  std::string::size_type position = 0; // Will be set to 0 at first iteration

  LOGM(VARP, logh, LEV_DEBUG, T_PRE, "Initiating parse order: %s",message.c_str());

  while (position != std::string::npos) {
    LOG(logh, LEV_DEBUG, T_PRE, "Entered loop");

    /* There is a specified ordering */
    std::string::size_type end_token = message.find_first_of(',', position);
    std::string attribute;

    if (end_token == std::string::npos)
      attribute = message.substr(position);
    else
      attribute = message.substr(position, end_token - position);

    LOGM(VARP, logh, LEV_DEBUG, T_PRE, "Attrib: %s",attribute.c_str());

    std::string::size_type divider = attribute.find(':');
    std::string fqan;

    if (divider == std::string::npos)
      fqan = attribute;
    else
      fqan = attribute.substr(0, divider) +
        "/Role=" + attribute.substr(divider+1);

    if (first.empty())
      first = fqan;

    LOGM(VARP, logh, LEV_DEBUG, T_PRE, "Order: %s",fqan.c_str());
    ordering.insert(std::make_pair<std::string, int>(fqan,order));
    order++;
    position = end_token;

    if (position != std::string::npos)
      position ++;
  }

  return first;
}

static void parse_targets(const std::string &message,
                          std::vector<std::string> &target)
{
  std::string::size_type position = 0; // Will be set to 0 at first iteration

  while (position != std::string::npos) {

    /* There is a specified ordering */
    std::string::size_type end_token = message.find_first_of(',',position);
    std::string attribute;

    if (end_token == std::string::npos)
      attribute = message.substr(position);
    else
      attribute = message.substr(position, end_token - position);

    target.push_back(attribute);
    position = end_token;

    if (position != std::string::npos)
      position ++;
  }
}

static bool not_in(std::string fqan, std::vector<std::string> fqans)
{
  return (find(fqans.begin(), fqans.end(), fqan) == fqans.end());
}

VOMSServer *selfpointer = NULL;

VOMSServer::VOMSServer(int argc, char *argv[]) : sock(0,NULL,50,false),
                                                 validity(86400),
                                                 logfile("/var/log/voms"),
                                                 gatekeeper_test(false),
                                                 daemon_port(DEFAULT_PORT),
                                                 foreground(false),
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
                                                 logf("%d:%h:%s[%p]: msg=\"%V:%T:%F (%f:%l):%m\""),
                                                 newformat(false),
                                                 insecure(false),
                                                 shortfqans(false),
                                                 do_syslog(false),
                                                 base64encoding(false),
                                                 nologfile(false),
                                                 max_active_requests(50)
{
  selfpointer = this;

  signal(SIGCHLD, sigchld_handler);
  signal(SIGTERM, sigterm_handler);
  ac = argc;
  av = argv;

  InitProxyCertInfoExtension(1);

  bool progversion = false;

  struct option opts[] = {
    {"help",            0, NULL,                      OPT_HELP},
    {"usage",           0, NULL,                      OPT_HELP},
    {"test",            0, (int *)&gatekeeper_test,   OPT_BOOL},
    {"conf",            1, NULL,                      OPT_CONFIG},
    {"port",            1, &daemon_port,              OPT_NUM},
    {"logfile",         1, (int *)&logfile,           OPT_STRING},
    {"globusid",        1, (int *)&dummy,             OPT_STRING},
    {"globuspwd",       1, (int *)&dummy,             OPT_STRING},
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
    {"mysql-port",      1, (int *)&mysql_port,        OPT_NUM},
    {"mysql-socket",    1, (int *)&mysql_socket,      OPT_STRING},
    {"passfile",        1, (int *)&passfile,          OPT_STRING},
    {"vo",              1, (int *)&voname,            OPT_STRING},
    {"uri",             1, (int *)&uri,               OPT_STRING},
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
    {"compat",          1, (int *)&dummyb,            OPT_BOOL},
    {"socktimeout",     1, &socktimeout,              OPT_NUM},
    {"logmax",          1, &logmax,                   OPT_NUM},
    {"newformat",       1, (int *)&newformat,         OPT_BOOL},
    {"skipcacheck",     1, (int *)&insecure,          OPT_BOOL},
    {"shortfqans",      0, (int *)&shortfqans,        OPT_BOOL},
    {"syslog",          0, (int *)&do_syslog,         OPT_BOOL},
    {"base64",          0, (int *)&base64encoding,    OPT_BOOL},
    {"nologfile",       0, (int *)&nologfile,         OPT_BOOL},
    {"max-reqs",         1, &max_active_requests,      OPT_NUM},
    {0, 0, 0, 0}
  };

  /*
   * Parse the command line arguments
   */

  set_usage("[-help] [-usage] [-conf parmfile] [-foreground] [-port port]\n"
            "[-logfile file] [-passfile file] [-vo voname]\n"
            "[-globus version]\n"
            "[-x509_cert_dir path] [-x509_cert_file file]\n"
            "[-x509_user_cert file] [-x509_user_key file]\n"
            "[-dbname name] [-username name] [-contactstring name]\n"
            "[-mysql-port port] [-mysql-socket socket] [-timeout limit]\n"
            "[-x509_user_proxy file] [-test] [-uri uri] [-code num]\n"
            "[-loglevel lev] [-logtype type] [-logformat format]\n"
            "[-logdateformat format] [-debug] [-backlog num] [-skipcacheck]\n"
            "[-version] [-sqlloc path] [-compat] [-logmax n] [-socktimeout n]\n"
            "[-shortfqans] [-newformat] [-syslog] [-base64] [-nologfile]\n"
            "[-max_reqs max_concurrent_request_number]\n");

  if (!getopts(argc, argv, opts))
    throw VOMSInitException("unable to read options");

  maingroup = snprintf_wrap("/%s", voname.c_str());

  if (socktimeout == -1)
    socktimeout = DEFAULT_TIMEOUT;

  if (code == -1)
    code = daemon_port;

  if (progversion) {
    std::cout << SUBPACKAGE << "\nVersion: " << VERSION << std::endl;
    std::cout << "Compiled: " << __DATE__ << " " << __TIME__ << std::endl;
    exit(0);
  }

  /* Test if logging can start. */
  if (!do_syslog) {
    struct stat statbuf;
    int dounlink = 1;
    int res = stat(logfile.c_str(), &statbuf);
    if (!res) {
      /* It exists. Must not be unlinked. */
      dounlink = 0;
    }

    int newfd = open(logfile.c_str(), O_WRONLY|O_CREAT|O_APPEND, S_IRUSR|S_IWUSR);
      
    if (newfd == -1) {
      fprintf(stderr, "logging could not start!  Logfile %s could not be opened, and syslogging is disabled.", logfile.c_str());
      exit(1);
    }
    if (dounlink)
      unlink(logfile.c_str());

    close(newfd);
  }

  if ((logh = LogInit())) {
      loglevels lev;

      switch(loglev) {
      case 1: lev = LEV_NONE; break;
      case 2: lev = LEV_ERROR; break;
      case 3: lev = LEV_WARN; break;
      case 4: lev = LEV_INFO; break;
      case 5: lev = LEV_DEBUG; break;
      default: lev = LEV_DEBUG; break;
      }
      if (lev == LEV_DEBUG)
        logt = T_STARTUP|T_REQUEST|T_RESULT;

      (void)LogLevel(logh, lev);
      (void)LogType(logh, logt);
      (void)SetCurLogType(logh, T_STARTUP);
      (void)LogService(logh, "vomsd");
      (void)LogFormat(logh, logf.c_str());

      if (!nologfile)
        (void)LogActivate(logh, "FILE");
      if (do_syslog)
        (void)LogActivate(logh, "SYSLOG");

      (void)LogOption(logh, "NAME", logfile.c_str());
      (void)LogOptionInt(logh, "MAXSIZE", logmax);
      (void)LogOption(logh, "DATEFORMAT", logdf.c_str());
  }
  else
    throw VOMSInitException("logging startup failure");

  LOGM(VARP, logh, LEV_INFO, T_PRE, "Package: %s", SUBPACKAGE);
  LOGM(VARP, logh, LEV_INFO, T_PRE, "Version: %s", VERSION);
  LOGM(VARP, logh, LEV_INFO, T_PRE, "Compiled: %s %s", __DATE__, __TIME__);
  for (int i = 0; i < argc; i++)
    LOGM(VARP, logh, LEV_DEBUG, T_PRE, "argv[%d] = \"%s\"", i, argv[i]);


  LOG(logh, LEV_INFO, T_PRE, "Reconfigured server.");
  if (!sqllib.empty()) {
    void * library = dlopen(sqllib.c_str(), RTLD_LAZY);
    if(!library) {
      LOG(logh, LEV_ERROR, T_PRE, ((std::string)("Cannot load library: " + sqllib)).c_str());
      std::cout << "Cannot load library: "<< sqllib << std::endl;
      char *message = dlerror();
      if (message) {
        LOG(logh, LEV_ERROR, T_PRE, message);
        std::cout << dlerror() << std::endl;
      }
      exit(1);
    }

    getlibversion = (gv)dlsym(library, "getDBInterfaceVersion");
    if (!getlibversion || getlibversion() != 3) {
      LOGM(VARP, logh, LEV_ERROR, T_PRE, "Old version of interface library found. Expecting >= 3, Found: %d", 
           (getlibversion ? getlibversion() : 1));
      std::cout << "Old version of interface library found. Expecting >= 3, Found: " << 
        (getlibversion ? getlibversion() : 1);
      exit(1);
    }

    NewDB = (cdb)dlsym(library, "CreateDB");
    if (!NewDB) {
      LOG(logh, LEV_ERROR, T_PRE, ((std::string)("Cannot find initialization symbol in: " + sqllib)).c_str());
      std::cout << "Cannot find initialization symbol in: "<< sqllib << dlerror() << std::endl;
      exit(1);
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

  db = NewDB();

  if (!db) {
    LOG(logh, LEV_ERROR, T_PRE, "Cannot initialize DB library.");
    std::cout << "Cannot initialize DB library.";
    exit(1);
  }

  db->setOption(OPTION_SET_PORT, &mysql_port);
  if (!mysql_socket.empty())
    db->setOption(OPTION_SET_SOCKET, (void*)mysql_socket.c_str());
  db->setOption(OPTION_SET_INSECURE, &insecure);

  if (!db->connect(dbname.c_str(), contactstring.c_str(), 
                   username.c_str(), passwd())) {
    LOGM(VARP, logh, LEV_ERROR, T_PRE, "Unable to connect to database: %s", 
         db->errorMessage());
    std::cout << "Unable to connect to database: " <<
      db->errorMessage() << std::endl;
    exit(1);
  }

  int v = 0;
  sqliface::interface *session = db->getSession();
  bool result = session->operation(OPERATION_GET_VERSION, &v, NULL);
  std::string errormessage = session->errorMessage();
  db->releaseSession(session);

  if (result) {
    if (v < 2) {
      LOGM(VARP, logh, LEV_ERROR, T_PRE, "Detected DB Version: %d. Required DB version >= 2", v);
      std::cerr << "Detected DB Version: " << v << ". Required DB version >= 2";

      throw VOMSInitException("wrong database version");
    }
  }
  else {

    LOGM(VARP, logh, LEV_ERROR, T_PRE, "Error connecting to the database : %s", errormessage.c_str());
    throw VOMSInitException((std::string("Error connecting to the database : ") + errormessage));
  }

  /* Check the value of max_active_requests passed in from voms configuration */
  if (max_active_requests <= 0){
    LOGM(VARP, logh, LEV_ERROR, T_PRE, "Wrong value set for max_reqs option. Resetting default value: 50");
    max_active_requests = 50;
  }

  LOGM(VARP, logh, LEV_INFO, T_PRE, "Maximum number of active requests: %d", max_active_requests);

  AdjustURI(uri, daemon_port);

  sock = GSISocketServer(daemon_port, NULL, backlog);

  /*
   * Dont use default env proxy cert for gatekeeper if run as root
   * this might get left over. You can still use -x509_user_proxy
   */

  unsetenv("X509_USER_PROXY");

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

  sock.SetLogger(logh);
  std::string msg = "URI: " + uri;

  LOGM(VARP, logh, LEV_INFO, T_PRE, "URI: %s", uri.c_str());

  AC_Init();
}

VOMSServer::~VOMSServer() {}

static char *cacertdir = (char*)"/etc/grid-security/certificates";
static char *hostcert  = (char*)"/etc/grid-security/hostcert.pem";
static char *hostkey   = (char*)"/etc/grid-security/hostkey.pem";

extern proxy_verify_desc *setup_initializers(char*);


void VOMSServer::Run()
{
  pid_t pid = 0;
  struct soap *sop = NULL;
  int active_requests = 0;
  int wait_status = 0;

  if (!x509_user_cert.empty())
    hostcert = (char*)x509_user_cert.c_str();

  if (!x509_user_key.empty())
    hostkey = (char *)x509_user_key.c_str();

  if (!x509_cert_dir.empty())
    cacertdir = (char *)x509_cert_dir.c_str();

  if (!debug) {
    if (daemon(0,0))
      exit(0);
  }

  fd_set rset;
  FD_ZERO(&rset);

  sop = soap_new();

  sop->fget = http_get;

  try {
    signal(SIGHUP, sighup_handler);
    LOG(logh, LEV_DEBUG, T_PRE, "Trying to open socket.");
    sock.Open();
    LOGM(VARP, logh, LEV_DEBUG, T_PRE, "Opened Socket: %d", sock.sck); 
    if (sock.sck == -1) {
      LOG(logh, LEV_ERROR, T_PRE, "Unable to bind socket");
      exit(1);
    }
    sock.SetTimeout(socktimeout);
    FD_SET(sock.sck, &rset);

    for (;;) {

      if (reload) {
        reload=0;
        UpdateOpts();
      }

      int selret = -1;

      do {
        selret = select(sock.sck+1, &rset, NULL, NULL, NULL);
      } while (selret <= 0);

      if (reload) {
        reload=0;
        UpdateOpts();
      }

      if (FD_ISSET(sock.sck, &rset)) {

        if (!sock.Listen()){
          LOGM(VARP, logh, LEV_ERROR, T_PRE, "Cannot listen on port %d", daemon_port);
          exit(1);
        } 

        (void)SetCurLogType(logh, T_REQUEST);

        active_requests++;

        // Wait for children termination before accepting
        // new requests if we exceeded the number of active
        // requests
        if (active_requests > max_active_requests){

          for (; active_requests > max_active_requests; --active_requests){
            LOGM( VARP, 
                logh, 
                LEV_INFO, 
                T_PRE, 
                "Reached number of maximum active requests: %d. Waiting for some children process to finish.", 
                max_active_requests);

            wait(&wait_status);
          }
        }

        pid = fork();

        if (pid) {

          LOGM(VARP, logh, LEV_INFO, T_PRE, "Started child executor with pid = %d", pid);
          sock.CloseListened();
        }

        if (!pid) {
          //Children process
          if (!sock.AcceptGSIAuthentication()){
            // Print out handshake errors to logs
            LOGM(VARP, logh, LEV_INFO, T_PRE, "Failed to authenticate peer.");
            LOGM(VARP, logh, LEV_INFO, T_PRE, "OpenSSL error: %s", sock.error.c_str());
            sock.CleanSocket();
            sock.Close();
            exit(1);
          }

          LOGM(VARP, logh, LEV_INFO, T_PRE, "SSL handshake completed succesfully.");
          LOGM(VARP, logh, LEV_INFO, T_PRE, "Self    : %s", sock.own_subject.c_str());
          LOGM(VARP, logh, LEV_INFO, T_PRE, "Self CA : %s", sock.own_ca.c_str());

          std::string user    = sock.peer_subject;
          std::string userca  = sock.peer_ca;
          subject = sock.own_subject;
          ca = sock.own_ca;

          LOGM(VARP, logh, LEV_INFO, T_PRE, "At: %s Received Contact :", timestamp());
          LOGM(VARP, logh, LEV_INFO, T_PRE, " user: %s", user.c_str());
          LOGM(VARP, logh, LEV_INFO, T_PRE, " ca  : %s", userca.c_str());
          LOGM(VARP, logh, LEV_INFO, T_PRE, " serial: %s", sock.peer_serial.c_str());
          std::string peek;

          (void)sock.Peek(3, peek);

          LOGM(VARP, logh, LEV_DEBUG, T_PRE, "peek data: %s", peek.c_str());

          if (peek == "0") {
            LOG(logh, LEV_DEBUG, T_PRE, "worhtless message for GSI compatibility. Discard");
            std::string tmp;
            sock.Receive(tmp); 
            LOGM(VARP, logh, LEV_DEBUG, T_PRE, " discarded: %s", tmp.c_str());
            (void)sock.Peek(3, peek);
            LOGM(VARP, logh, LEV_DEBUG, T_PRE, "peek data: %s", peek.c_str());
          }

          // This is where all the handling logic happens now, when
          // a REST request is received.

          LOG(logh, LEV_DEBUG, T_PRE, "Starting Execution.");
          if (peek == "GET") {

            LOG(logh, LEV_DEBUG, T_PRE, "Received REST request.");
            sop->socket = sock.newsock;
            sop->ssl = sock.ssl;
            sop->fparse(sop);

            sock.Close();
            exit(0);
          }

          // Old legacy interface (pre voms 2.0)
          Execute(sock.own_key, sock.own_cert, sock.peer_cert);
          sock.Close();
          exit(0);

        } // Children execution frame   
      } // if (FD_ISSET(sock.sck, &rset))

      FD_ZERO(&rset);
      FD_SET(sock.sck, &rset);

    } // Outer foor loop
  }catch (...) {}

}

bool VOMSServer::makeAC(vomsresult& vr, EVP_PKEY *key, X509 *issuer, 
			X509 *holder, const std::string &message)
{
  LOGM(VARP, logh, LEV_DEBUG, T_PRE, "Received Request: %s", message.c_str());

  struct request r;

  if (!XML_Req_Decode(message, r)) {
    LOGM(VARP, logh, LEV_ERROR, T_PRE, "Unable to interpret command: %s",message.c_str());
    vr.setError(ERR_NO_COMMAND, "Unable to intepret command: " + message);
    return false;
  }

  std::vector<std::string> comm = r.command;

  vr.setBase64(base64encoding | r.base64);

  int requested = r.lifetime;

  std::vector<std::string> targs;

  ordering.clear();

  parse_targets(r.targets, targs);

  std::string tmp="";
  std::string command=comm[0];
  bool result = true;
  bool result2 = true;

  /* Interpret user requests */

  /* Shorten validity if needed */

  if (requested != 0) {
    if (requested == -1)
      requested = validity;
    else if (validity < requested) {
      vr.setError(WARN_SHORT_VALIDITY,
                  uri + ": The validity of this VOMS AC in your proxy is shortened to " +
                  stringify(validity, tmp) + " seconds!");
      requested = validity;
    }
  }

  std::vector<std::string> fqans;
  std::vector<gattrib> attribs;
  signed long int uid = -1;

  sqliface::interface *newdb = db->getSession();

  if (!newdb) {
    vr.setError(ERR_WITH_DB, voname + ": Problems in DB communication.");
    LOGM(VARP, logh, LEV_ERROR, T_PRE, "%s: Problems in DB communication.", voname.c_str());
    return false;
  }

  /* Determine user ID in the DB */

  if ((uid = get_userid(newdb, holder, voname, vr)) == -1) {
    db->releaseSession(newdb);
    return false;
  }

  LOGM(VARP, logh, LEV_INFO, T_PRE, "Userid = \"%ld\"", uid);

  bool setuporder = false;

  if (r.order.empty())
    setuporder = true;

  int k = 0;


  /* Parse and execute requests */

  std::vector<std::string>::const_iterator end = comm.end();
  for(std::vector<std::string>::const_iterator i = comm.begin(); i != end; ++i) {
    char commletter = '\0';
    command = comm[k++];
    char *group = NULL;
    char *role = NULL;
    bool valid = determine_group_and_role(*i, &commletter, &group, &role);

    LOGM(VARP, logh, LEV_INFO, T_PRE, "Next command : %s", i->c_str());

    if (valid) {

      /* Interpret request by first character */
      switch (commletter) {
      case 'A':
        if ((result = newdb->operation(OPERATION_GET_ALL, &fqans, uid)))
          result2 = newdb->operation(OPERATION_GET_ALL_ATTRIBS, &attribs, uid);
        break;

      case 'R':
        if ((result = newdb->operation(OPERATION_GET_ROLE, &fqans, uid, role)))
          result2 = newdb->operation(OPERATION_GET_ROLE_ATTRIBS, &attribs, uid, role);
        result2 |= newdb->operation(OPERATION_GET_GROUPS_ATTRIBS, &attribs, uid);
        break;

      case 'G':
        if ((result = newdb->operation(OPERATION_GET_GROUPS, &fqans, uid))) {
          if (not_in(std::string(group), fqans))
            result = false;
          else
            result2 = newdb->operation(OPERATION_GET_GROUPS_ATTRIBS, &attribs, uid);
        }
        break;

      case 'B':
        if ((result = newdb->operation(OPERATION_GET_GROUPS_AND_ROLE, &fqans, uid, group, role)))
          result2 = newdb->operation(OPERATION_GET_GROUPS_AND_ROLE_ATTRIBS, &attribs, uid, group, role);
        result2 |= newdb->operation(OPERATION_GET_GROUPS_ATTRIBS, &attribs, uid);
        break;

      case 'N':
        result = newdb->operation(OPERATION_GET_ALL, &fqans, uid);
        break;

      default:
        result = false;
        LOGM(VARP, logh, LEV_ERROR, T_PRE, "Unknown Command \"%c\"", commletter);
        break;
      }

      if (setuporder)
        r.order = addtoorder(r.order, group, role);
    }
    else
      result = false;

    free(group); // role is automatically freed.

    if(!result) {
      LOGM(VARP, logh, LEV_DEBUG, T_PRE, "While retrieving fqans: %s", newdb->errorMessage());
      break;
    }

    if (!result2)
      LOGM(VARP, logh, LEV_DEBUG, T_PRE, "While retrieving attributes: %s", newdb->errorMessage());
  }

  db->releaseSession(newdb);

  /* Error in executing queries ? */
  if (!result) {
    LOG(logh, LEV_ERROR, T_PRE, "Error in executing request!");

    std::string msg;

    if (command == (std::string("G/")+ voname) ||
        command == (std::string("/") + voname))
      msg = voname + ": User unknown to this VO.";
    else
      msg = voname + ": Unable to satisfy " + command + " Request!";

    vr.setError(ERR_NOT_MEMBER, msg);

    LOG(logh, LEV_ERROR, T_PRE, msg.c_str());

    return false;
  }

  /* do ordering */
  LOGM(VARP, logh, LEV_DEBUG,T_PRE, "ordering: %s", r.order.c_str());

  std::string firstfqan = parse_order(r.order, ordering);

  // remove duplicates
  std::sort(fqans.begin(), fqans.end());
  fqans.erase(std::unique(fqans.begin(), fqans.end()), fqans.end());

  // remove duplicates from attributes
  std::sort(attribs.begin(), attribs.end());
  attribs.erase(std::unique(attribs.begin(), attribs.end()), 
                attribs.end());

  if(result && !fqans.empty()) {
    orderattribs(fqans);
  }

  if (!firstfqan.empty()) {
    std::vector<std::string>::iterator i = fqans.begin();
    if (i != fqans.end()) {
      LOGM(VARP, logh, LEV_DEBUG, T_PRE,  "fq = %s", firstfqan.c_str());
      if (*i != firstfqan)
        vr.setError(WARN_NO_FIRST_SELECT, "FQAN: " + *i + " is not the first selected!\n");
    }
  }


  if(!fqans.empty()) {
    /* check whether the user is allowed to requests those attributes */
    vomsdata vd("", "");
    vd.SetVerificationType((verify_type)(VERIFY_SIGN));
    vd.Retrieve(sock.actual_cert, sock.peer_stack, RECURSE_DEEP);

    /* find the attributes corresponding to the vo */
    std::vector<std::string> existing;
    std::vector<voms>::iterator end = (vd.data).end();
    for(std::vector<voms>::iterator index = (vd.data).begin(); index != end; ++index) {
      if(index->voname == voname)
        existing.insert(existing.end(),
                     index->fqan.begin(),
                     index->fqan.end());
    }
  
    // Adjust for long/short format
    if (!shortfqans && !fqans.empty()) {
      std::vector<std::string> newfqans(fqans);
      fqans.clear();
      std::vector<std::string>::iterator i = newfqans.begin();
      std::vector<std::string>::iterator end = newfqans.end();

      while (i != end) {
        std::string fqan = *i;
        LOGM(VARP, logh, LEV_DEBUG, T_PRE, "Initial FQAN: %s", fqan.c_str());
        if (fqan.find("/Role=") != std::string::npos)
          fqan += "/Capability=NULL";
        else
          fqan += "/Role=NULL/Capability=NULL";
        LOGM(VARP, logh, LEV_DEBUG, T_PRE, "Processed FQAN: %s", fqan.c_str());
        fqans.push_back(fqan);
        ++i;
      }
    }

    /* if attributes were found, only release an intersection beetween the requested and the owned */
    std::vector<std::string>::iterator fend = fqans.end();
    bool subset = false;

    if (!existing.empty())
      if (fqans.erase(remove_if(fqans.begin(),
                                fqans.end(),
                                bind2nd(std::ptr_fun(not_in), existing)),
                      fqans.end()) != fend)
        subset = true;

    if (subset) {
      // remove attributes for qualifier which had been removed
      attribs.erase(remove_if(attribs.begin(), attribs.end(),
                              bind2nd(std::ptr_fun(checkinside), fqans)),
                    attribs.end());
    }


    // no attributes can be send
    if (fqans.empty()) {
      LOG(logh, LEV_ERROR, T_PRE, "Error in executing request!");
      vr.setError(ERR_ATTR_EMPTY, voname + " : your certificate already contains attributes, only a subset of them can be issued.");
      return false;
    }

    // some attributes can't be send
    if(subset) {
      LOG(logh, LEV_ERROR, T_PRE, "Error in executing request!");
      vr.setError(WARN_ATTR_SUBSET, voname + " : your certificate already contains attributes, only a subset of them can be issued.");
    }
  }

  if (!fqans.empty()) {
    // test logging retrieved attributes
    std::vector<std::string>::const_iterator end = fqans.end();

    for (std::vector<std::string>::const_iterator i = fqans.begin(); i != end; ++i)
      LOGM(VARP, logh, LEV_INFO, T_PRE, "Request Result: %s",  (*i).c_str());

    if (LogLevelMin(logh, LEV_DEBUG)) {
      if(result && !attribs.empty()) {
        std::vector<gattrib>::const_iterator end = attribs.end();
        for(std::vector<gattrib>::const_iterator i = attribs.begin(); i != end; ++i)
          LOGM(VARP, logh, LEV_DEBUG, T_PRE,  "User got attributes: %s", i->str().c_str());
      }
      else
        LOGM(VARP, logh, LEV_DEBUG, T_PRE,  "User got no attributes or something went wrong searching for them.");
    }

    ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

    std::string codedac;
    std::string data;

    if (comm[0] != "N") {
      int res = 1;
      BIGNUM * serial = get_serial();

      if (!serial)
        LOG(logh, LEV_ERROR, T_PRE, "Can't get Serial Number!");
      else {
        /* Make AC */
        AC *a = AC_new();

        LOGM(VARP, logh, LEV_DEBUG, T_PRE, "length = %d", i2d_AC(a, NULL));
        if (a) {
          std::vector<std::string> attributes_compact;

          std::vector<gattrib>::const_iterator end = attribs.end();
          for(std::vector<gattrib>::const_iterator i = attribs.begin(); i != end; ++i)
            attributes_compact.push_back(i->str());

          res = createac(issuer, sock.own_stack, holder, key, serial,
                         fqans, targs, attributes_compact, &a, voname, uri, requested, !newformat,
                         NULL);
        }

        /* Encode AC */
        if (!res) {
          unsigned int len = i2d_AC(a, NULL);

          unsigned char *tmp = (unsigned char *)OPENSSL_malloc(len);
          unsigned char *ttmp = tmp;

          LOGM(VARP, logh, LEV_DEBUG, T_PRE, "length = %d", len);

          if (tmp) {
            i2d_AC(a, &tmp);
            codedac = std::string((char *)ttmp, len);
          }
          free(ttmp);
        }
        else
          vr.setError(ERR_NOT_MEMBER, get_error(res));

        AC_free(a);
        BN_free(serial);
      }

      if (res || codedac.empty()) {
        LOG(logh, LEV_ERROR, T_PRE, "Error in executing request!");
        vr.setError(ERR_NOT_MEMBER, ": Unable to satisfy " + command + " request due to database error.");
        return false;
      }
    }
    else {
      /* comm[0] == "N" */

      std::vector<std::string>::const_iterator end = fqans.end();
      for (std::vector<std::string>::const_iterator i = fqans.begin(); i != end; ++i)
        data += (*i).c_str() + std::string("\n");
    }

    (void)SetCurLogType(logh, T_RESULT);

    vr.setAC(codedac);
    vr.setData(data);
    return true;
  }
  else {
    vr.setError(ERR_NOT_MEMBER, std::string("You are not a member of the ") + voname + " VO!");
    return false;
  }
}

void
VOMSServer::Execute(EVP_PKEY *key, X509 *issuer, X509 *holder)
{
  std::string message;

  if (!sock.Receive(message)) {
    LOG(logh, LEV_ERROR, T_PRE, "Unable to receive request.");
    sock.CleanSocket();
  }

  if (message == "0") {
    /* GSI Clients may send a "0" first (spurious) message. Just ignore it. */
    if (!sock.Receive(message)) {
      LOG(logh, LEV_ERROR, T_PRE, "Unable to receive request.");
      sock.CleanSocket();
    }
  }

  vomsresult vr;
  (void)makeAC(vr, key, issuer, holder, message);
  std::string answer = vr.makeXMLAnswer();

  LOGM(VARP, logh, LEV_DEBUG, T_PRE, "Sending: %s", answer.c_str());
  sock.Send(answer);
}

void VOMSServer::UpdateOpts(void)
{
  std::string nlogfile = logfile;
  int nblog = 50;
  bool progversion = false;
  int nport;

  struct option opts[] = {
    {"test",            0, (int *)&gatekeeper_test,   OPT_BOOL},
    {"conf",            1, NULL,                      OPT_CONFIG},
    {"port",            1, &nport,                    OPT_NUM},
    {"logfile",         1, (int *)&nlogfile,          OPT_STRING},
    {"globusid",        1, (int *)&dummy,             OPT_STRING},
    {"globuspwd",       1, (int *)&dummy,             OPT_STRING},
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
    {"mysql-port",      1, (int *)&mysql_port,        OPT_NUM},
    {"mysql-socket",    1, (int *)&mysql_socket,      OPT_STRING},
    {"passfile",        1, (int *)&passfile,          OPT_STRING},
    {"vo",              1, (int *)&voname,            OPT_STRING},
    {"uri",             1, (int *)&uri,               OPT_STRING},
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
    {"compat",          0, (int *)&dummyb,            OPT_BOOL},
    {"socktimeout",     1, &socktimeout,              OPT_NUM},
    {"logmax",          1, &logmax,                   OPT_NUM},
    {"newformat",       0, (int *)&newformat,         OPT_BOOL},
    {"skipcacheck",     0, (int *)&insecure,          OPT_BOOL},
    {"shortfqans",      0, (int *)&shortfqans,        OPT_BOOL},
    {"syslog",          0, (int *)&do_syslog,         OPT_BOOL},
    {"base64",          0, (int *)&base64encoding,    OPT_BOOL},
    {"nologfile",       0, (int *)&nologfile,         OPT_BOOL},
    {0, 0, 0, 0}
  };

  (void)SetCurLogType(logh, T_STARTUP);

  nlogfile = "";

  if (!getopts(ac, av, opts)) {
    LOG(logh, LEV_ERROR, T_PRE, "Unable to read options!");
    throw VOMSInitException("unable to read options");
  }

  if (nlogfile.size() != 0) {
    LOGM(VARP, logh, LEV_INFO, T_PRE, "Attempt redirecting logs to: %s", logfile.c_str());

    LogOption(logh, "NAME", nlogfile.c_str());

    logfile = nlogfile;
  }

  LogOptionInt(logh, "MAXSIZE", logmax);
  LogOption(logh, "DATEFORMAT", logdf.c_str());

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

    (void)LogLevel(logh, lev);

    if (lev == LEV_DEBUG)
      logt = T_STARTUP|T_REQUEST|T_RESULT;

    (void)LogType(logh, logt);
    (void)SetCurLogType(logh, T_STARTUP);
    (void)LogService(logh, "vomsd");
    (void)LogFormat(logh, logf.c_str());
  }

  if (nport != daemon_port) {
    if (!sock.ReOpen(daemon_port = nport, nblog, true))
      LOG(logh, LEV_ERROR, T_PRE, "Failed to reopen socket! Server in unconsistent state.");
  }
  else if (nblog != backlog)
    sock.AdjustBacklog(backlog = nblog);

  AdjustURI(uri, daemon_port);

  if (!getpasswd(passfile, logh)){
    throw VOMSInitException("can't read password file!");
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

  LOG(logh, LEV_INFO, T_PRE, "Reconfigured server.");
}

static BIGNUM *get_serial()
{
  unsigned char uuid[16];
  initialize_uuid_generator();
  generate_uuid(uuid);
  BIGNUM *number = NULL;

  return BN_bin2bn(uuid, 16, number);
}

static bool determine_group_and_role(std::string command, char *comm, char **group, char **role)
{
  *role = *group = NULL;

  if (command.empty())
    return false;

  char *string = strdup(command.c_str()+1);

  if (strcmp(string, "all") == 0) {
    *comm = 'A';
    *role = *group = NULL;
    free(string);
    return true;
  }

  if (string[0] != '/') {
    /* old syntax */
    *comm = command[0];

    *group = string;

    switch (*comm) {
    case 'G':
      *role = NULL;
      break;
    case 'R':
      *role = string;
      break;
    case 'B':
      *role = strchr(string, ':');
      if (*role) {
        (*role) = '\0';
        (*role)++;
      }
      break;
    }
  }
  else {
    /* fqan syntax */
    char *divider  = strstr(string, "/Role=");
    char *divider2 = strstr(string, ":");
    if (divider) {
      if (divider == string) {
        *group = NULL;
        *role = divider + 6;
        *comm = 'R';
      }
      else {
        *group = string;
        *role = divider + 6;
        *divider='\0';
        *comm='B';
      }
    }
    else if (divider2) {
      if (divider2 == string) {
        *group = NULL;
        *role = divider2+1;
        *comm = 'R';
      }
      else {
        *group = string;
        *role = divider2+1;
        *divider2 = '\0';
        *comm = 'B';
      }
    }
    else {
      *group = string;
      *role = NULL;
      *comm='G';
    }
    if (strcmp(*group, "/") == 0) {
      free(string);
      *role = *group = NULL;
      *comm = 'A';
    }
    if (strcmp(*group, "//") == 0) {
      free(string);
      *role = *group = NULL;
      *comm='N';
    }
  }

  if (!acceptable(*group) || !acceptable(*role)) {
    free(string);
    *role = *group = NULL;
    return false;
  }

  return true;
}


static bool checkinside(gattrib g, std::vector<std::string> list) 
{
  return !g.qualifier.empty() && not_in(g.qualifier, list);
}

static signed long int get_userid(sqliface::interface *db, X509 *cert, const std::string& voname, vomsresult &vr)
{
  signed long int uid = -1;

  if (!db->operation(OPERATION_GET_USER, &uid, cert)) {
    std::string message = db->errorMessage() ? db->errorMessage() : "unknown";

    LOG(logh, LEV_ERROR, T_PRE, "Error in executing request!");
    LOG(logh, LEV_ERROR, T_PRE, message.c_str());

    int code = db->error();
  
    std::string msg;

    if (code == ERR_USER_SUSPENDED) {
      msg = "User is currently suspended!\nSuspension reason: " + 
        std::string(message);

      vr.setError(ERR_SUSPENDED, msg);
    }
    else if (code != ERR_NO_DB) {
      msg = voname + ": User unknown to this VO.";
      vr.setError(ERR_NOT_MEMBER, msg);
    }
    else {
      msg = voname + ": Problems in DB communication: " + message;
      vr.setError(ERR_WITH_DB, msg);
    }

    LOG(logh, LEV_ERROR, T_PRE, msg.c_str());
  }
  return uid;
}

static std::string addtoorder(std::string previous, char *group, char *role)
{
  if (!group && !role)
    return previous;

  if (!previous.empty())
    previous += ",";

  previous +=
    (group ? std::string(group) : "") +
    (role  ? std::string("/Role=") + role : "");

  return previous;
}

static void AdjustURI(std::string &uri, int port)
{
  if (uri.empty()) {
    int   hostnamesize = 50;
    char *hostname = new char[1];
    int ok = 0;

    do {
      delete[] hostname;
      hostname = new char[hostnamesize];
      ok = gethostname(hostname, hostnamesize);
      hostnamesize += 50;
    } while (ok);
    
    std::string temp;

    uri = std::string(hostname) + ":" + stringify(port, temp);

    delete[] hostname;
  }
}
