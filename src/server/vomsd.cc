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
#include "proxycertinfo.h"
}

#include <sstream>

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

static bool file_is_readable(const char* filename){
  std::ifstream f(filename);
  return f.good();
}

std::string vomsresult::makeRESTAnswer(int& code)
{
  std::string output = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><voms>";
  code = SOAP_HTML;

  if (ac != "A" && !ac.empty()){
    std::string encoded_ac = Encode(ac,true);
    output += "<ac>"+encoded_ac+"</ac>";
  }

  if (!data.empty()){
    std::string encoded_data = Encode(data,true);
    output += "<bitstr>"+encoded_data+"</bitstr>";
  }

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
static long long get_userid(sqliface::interface *db, X509 *cert, const std::string& voname, vomsresult &vr);
static std::string addtoorder(std::string previous, char *group, char *role);
static bool determine_group_and_role(std::string command, char *comm, char **group, char **role);
static BIGNUM *get_serial();
static void sighup_handler(int signo);
static void sigterm_handler(int signo);
static bool compare(const std::string &lhs, const std::string &rhs);
static void orderattribs(std::vector<std::string> &v);
static std::string parse_order(const std::string &message, ordermap &ordering);
static void parse_targets(const std::string &message, std::vector<std::string> &target);
static bool not_in(std::string fqan, std::vector<std::string> fqans);
static void AdjustURI(std::string &uri, int port);

static int active_requests = 0;

static void
sigchld_handler(int signo)
{

  int save_errno = errno;
  pid_t pid;
  int status;
  
  do{

    pid = waitpid(-1,&status, WNOHANG);

    if (pid > 0)  
    {
      active_requests--;
      if ( active_requests < 0 )
        active_requests = 0;
    }

  } while ((pid > 0) || (pid < 0 && errno == EINTR));

  errno = save_errno;
}

static void
sighup_handler(int signo)
{
  reload = 1;
}

static void
sigterm_handler(int signo)
{
  exit(1);
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
    ordering.insert(std::make_pair(fqan,order));
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
    throw voms_init_error("unable to read options");

  maingroup = snprintf_wrap("/%s", voname.c_str());

  if (socktimeout == -1)
    socktimeout = DEFAULT_TIMEOUT;

  if (code == -1)
    code = daemon_port;

  if (progversion) {
    std::cout << SUBPACKAGE << "\nVersion: " << VERSION << std::endl;
    std::cout << "Compiled: " << __DATE__ << " " << __TIME__ << std::endl;
    return;
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
      throw voms_execution_error("Logging system startup error.");
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
    throw voms_init_error("logging startup failure");

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
      throw voms_init_error("Cannot load database library");
    }

    getlibversion = (gv)dlsym(library, "getDBInterfaceVersion");
    if (!getlibversion || getlibversion() != 3) {

      std::string error_msg("Old version of interface library found. Expecting >= 3, found: ");
      error_msg += (getlibversion ? getlibversion() : 1);

      LOGM(VARP, logh, LEV_ERROR, T_PRE, error_msg.c_str());
      throw voms_init_error(error_msg);
    }

    NewDB = (cdb)dlsym(library, "CreateDB");
    if (!NewDB) {
      std::string error_msg("Cannot find initialization symbol in: ");
      error_msg += sqllib;

      LOG(logh, LEV_ERROR, T_PRE, error_msg.c_str());
      throw voms_init_error(error_msg);
    }

  }
  else {
    LOG(logh, LEV_ERROR, T_PRE, "Empty SQL library. Cannot start." );
    throw voms_init_error("Empty SQL library. Cannot start.");
  }

  if (!getpasswd(passfile, logh))  {
    LOG(logh, LEV_ERROR, T_PRE, "can't read password file!\n");
    throw voms_init_error("can't read password file!");
  }

  if(contactstring.empty())
    contactstring = (std::string)"localhost";

  db = NewDB();

  if (!db) {
    LOG(logh, LEV_ERROR, T_PRE, "Cannot initialize DB library.");
    throw voms_init_error("Cannot initialize DB library.");
  }

  db->setOption(OPTION_SET_PORT, &mysql_port);
  if (!mysql_socket.empty())
    db->setOption(OPTION_SET_SOCKET, (void*)mysql_socket.c_str());
  db->setOption(OPTION_SET_INSECURE, &insecure);

  if (!db->connect(dbname.c_str(), contactstring.c_str(), 
                   username.c_str(), passwd())) {

    std::string error_msg("Unable to connect to database: ");
    error_msg += db->errorMessage();

    LOGM(VARP, logh, LEV_ERROR, T_PRE, error_msg.c_str());
    throw voms_init_error(error_msg);
  }

  int v = 0;
  sqliface::interface *session = db->getSession();
  bool result = session->operation(OPERATION_GET_VERSION, &v, NULL);
  std::string errormessage = session->errorMessage();
  db->releaseSession(session);

  if (result) {
    if (v < 2) {
      LOGM(VARP, logh, LEV_ERROR, T_PRE, "Detected DB Version: %d. Required DB version >= 2", v);
      throw voms_init_error("Wrong database version");
    }
  }
  else {

    LOGM(VARP, logh, LEV_ERROR, T_PRE, "Error connecting to the database : %s", errormessage.c_str());
    throw voms_init_error((std::string("Error connecting to the database : ") + errormessage));
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
  int wait_status = 0;

  if (!x509_user_cert.empty())
    hostcert = (char*)x509_user_cert.c_str();

  if (!x509_user_key.empty())
    hostkey = (char *)x509_user_key.c_str();

  if (!x509_cert_dir.empty())
    cacertdir = (char *)x509_cert_dir.c_str();

  // Check AA certificate and private key can be opened
  // or refuse to start up
 
  if (!file_is_readable(hostcert)) {
    LOGM(VARP, logh, LEV_ERROR, T_PRE, "Error opening VOMS certificate file: %s", hostcert); 
    throw voms_init_error(std::string("Cannot open file: ")+hostcert);
  }

  if (!file_is_readable(hostkey)) {
    LOGM(VARP, logh, LEV_ERROR, T_PRE, "Error opening VOMS private key file: %s", hostkey); 
    throw voms_init_error(std::string("Cannot open file: ")+hostkey);
  }

  if (!debug) {
    if (daemon(0,0))
      return;
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
      throw voms_execution_error("Unable to bind socket");
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

          std::ostringstream error_msg;
          error_msg << "Cannot listen on port " << daemon_port;

          LOGM(VARP, logh, LEV_ERROR, T_PRE, error_msg.str().c_str());
          throw voms_execution_error(error_msg.str());
        } 

        (void)SetCurLogType(logh, T_REQUEST);

        // Wait for children termination before accepting
        // new requests if we exceeded the number of active
        // requests
        if (active_requests > max_active_requests){

          LOGM( VARP, 
              logh, 
              LEV_INFO, 
              T_PRE, 
              "Reached number of maximum active requests: %d. Waiting for some children process to finish.", 
              max_active_requests);

          wait(&wait_status);
          active_requests--;

        }

        pid = fork();

        if (pid) {
          // Parent process
          active_requests++;
          LOGM(VARP, logh, LEV_INFO, T_PRE, "Started child executor with pid = %d. Active requests = %d", 
            pid, active_requests);

          sock.Close();

          // Reset socket descriptors
          FD_ZERO(&rset);
          FD_SET(sock.sck, &rset);
        }

        if (!pid) {
          //Children process

          if (!sock.AcceptGSIAuthentication()){

            LOGM(VARP, logh, LEV_INFO, T_PRE, sock.error.c_str());

            for (std::vector<std::string>::const_iterator err_it = sock.GetOpenSSLErrors().begin();
                err_it != sock.GetOpenSSLErrors().end();
                ++err_it){

              std::string err_string = *err_it;
              LOGM(VARP, logh, LEV_INFO, T_PRE, err_string.c_str());

            }

            sock.CleanSocket();
            sock.Close();
            return;
          }

          LOGM(VARP, logh, LEV_INFO, T_PRE, "SSL handshake completed successfully.");

          std::string user    = sock.peer_subject;
          std::string userca  = sock.peer_ca;
          subject = sock.own_subject;
          ca = sock.own_ca;

          LOGM(VARP, logh, LEV_INFO, T_PRE, "Received request from: %s, %s (serial: %s)", 
            user.c_str(), 
            userca.c_str(), 
            sock.peer_serial.c_str());

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
          if (peek == "GET") {

            LOG(logh, LEV_DEBUG, T_PRE, "Received HTTP request...");
            sop->socket = sock.newsock;
            sop->ssl = sock.ssl;

            // GSOAP will handle this
            // newer versions of gsoap don't call the http handlers (eg fget) in fparse
            // fparse returns SOAP_STOP if any of the handlers were called instead of SOAP_OK (older versions)
            // if the return value is SOAP_OK then no hander has been called (newer versions) and we call
            // fget manually if it's a get request (SOAP_GET)
            if(sop->fparse(sop) == SOAP_OK && sop->status == SOAP_GET)
              sop->fget(sop);

            sock.Close();
          } else {

            // Old legacy interface (pre voms 2.0)
            LOG(logh, LEV_DEBUG, T_PRE, "Received VOMS legacy protocol request...");
            Execute(sock.own_key, sock.own_cert, sock.peer_cert);
            sock.Close();
          }

          return;
        } // Children execution frame   
      } 
    } // Outer foor loop
  }catch (voms_execution_error &e){
    LOGM(VARP, logh, LEV_ERROR, T_PRE, e.what());
  }
  catch (...) 
  {
    LOGM(VARP, logh, LEV_WARN, T_PRE, "Exception caught in main server loop (and swallowed).");
  }
}

bool VOMSServer::makeAC(vomsresult& vr, EVP_PKEY *key, X509 *issuer, 
      X509 *holder, const std::string &message)
{
  LOGM(VARP, logh, LEV_DEBUG, T_PRE, "Received Request: %s", message.c_str());

  struct request r;

  if (!XML_Req_Decode(message, r)) {
    LOGM(VARP, logh, LEV_ERROR, T_PRE, "Unable to interpret command: %s",message.c_str());
    vr.setError(ERR_NO_COMMAND, "Unable to interpret command: " + message);
    return false;
  }

  std::vector<std::string> comm = r.command;

  vr.setBase64(base64encoding | r.base64);

  int requested = r.lifetime;

  if (requested < 0){
    requested = validity;
  }

  std::vector<std::string> targs;

  ordering.clear();

  parse_targets(r.targets, targs);

  std::string tmp;
  
  if (comm.empty()){
    throw voms_execution_error("Invalid VOMS request received: no command found!");
  }
  
  std::string command(comm[0]);
  bool result = true;
  bool result2 = true;

  /* Interpret user requests */

  /* Shorten validity if needed */

  if (requested != 0) {
    if (requested == -1){

      requested = validity;

    } else if (validity < requested) {

      requested = validity;
      std::ostringstream msg;

      msg << uri << ": The validity of this VOMS AC in your proxy is shortened to "
        << validity << " seconds!";

      vr.setError(WARN_SHORT_VALIDITY, msg.str());
    }
  }

  std::vector<std::string> fqans;
  std::vector<gattrib> attribs;

  sqliface::interface *newdb = db->getSession();

  if (!newdb) {
    vr.setError(ERR_WITH_DB, voname + ": Problems in DB communication.");
    LOGM(VARP, logh, LEV_ERROR, T_PRE, "%s: Problems in DB communication.", voname.c_str());
    return false;
  }

  /* Determine user ID in the DB */
  long long uid = -1;

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
      LOGM(VARP, logh, LEV_DEBUG, T_PRE, "Error while retrieving fqans: %s", newdb->errorMessage());
      break;
    }

    if (!result2)
      LOGM(VARP, logh, LEV_DEBUG, T_PRE, "Error while retrieving generic attributes: %s", newdb->errorMessage());
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
      msg = voname + ": Unable to satisfy " + command + " request!";

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
      LOGM(VARP, logh, LEV_DEBUG, T_PRE,  "first fqan = %s", firstfqan.c_str());
      if (*i != firstfqan)
        vr.setError(WARN_NO_FIRST_SELECT, "FQAN: " + *i + " is not the first selected!\n");
    }
  }

  // Adjust for long/short format
  if (!shortfqans && !fqans.empty()) {

    LOGM(VARP, logh, LEV_DEBUG, T_PRE,  "Translating FQANs to long format.");
    std::vector<std::string> newfqans(fqans);
    fqans.clear();
    std::vector<std::string>::iterator i = newfqans.begin();
    std::vector<std::string>::iterator end = newfqans.end();

    while (i != end) {
      std::string fqan = *i;
      if (fqan.find("/Role=") != std::string::npos)
        fqan += "/Capability=NULL";
      else
        fqan += "/Role=NULL/Capability=NULL";
      LOGM(VARP, logh, LEV_DEBUG, T_PRE, "Translated FQAN: %s", fqan.c_str());
      fqans.push_back(fqan);
      ++i;
    }
  }

  if(!fqans.empty()) {
    
    LOGM(VARP, logh, LEV_DEBUG, T_PRE,  "Checking if user comes with valid fqans.");

    vomsdata vd("", "");
    vd.SetVerificationType((verify_type)(VERIFY_SIGN | VERIFY_DATE));
    
    if (!vd.Retrieve(sock.actual_cert, sock.peer_stack, RECURSE_DEEP)){

      std::string voms_error = vd.ErrorMessage();

      LOGM(VARP, logh, LEV_DEBUG, T_PRE,  
        "No valid VOMS attributes found in client cert chain. VOMS retrieve error: %s",
        voms_error.c_str());
    }

    std::vector<std::string> existing;
    std::vector<voms>::iterator end = (vd.data).end();

    for (std::vector<voms>::iterator index = (vd.data).begin(); index != end; ++index) 
    {
      if (index->voname == voname)
      {
        std::vector<std::string>::iterator fqan_it = index->fqan.begin();

        for ( ; fqan_it != index->fqan.end(); ++fqan_it)
        {
          LOGM(VARP, logh, LEV_DEBUG, T_PRE,  "Found fqan in user credential: %s", fqan_it->c_str());
          existing.push_back(*fqan_it);
        }
      }
    }


    /* if attributes were found, only release an intersection beetween the requested and the owned */
    std::vector<std::string>::iterator fend = fqans.end();
    bool subset = false;

    if (!existing.empty())
    {
      LOGM(VARP, logh, LEV_DEBUG, T_PRE,  "User comes with valid fqans for this VO. Computing fqans intersection.");
      if (fqans.erase(remove_if(fqans.begin(),
                                fqans.end(),
                                bind2nd(std::ptr_fun(not_in), existing)),
                      fqans.end()) != fend)
      {
        LOGM(VARP, logh, LEV_DEBUG, T_PRE,  "Only a subset of the requested attributes will be returned.");
        subset = true;
      }
    }

    if (subset) 
    {
      
      LOGM(VARP, logh, LEV_DEBUG, T_PRE,  "Dropping generic attributes for fqans which cannot be issued for current request.");
      attribs.erase(remove_if(attribs.begin(), attribs.end(),
                              bind2nd(std::ptr_fun(checkinside), fqans)),
                    attribs.end());
    }

    if (fqans.empty()) 
    {
      LOG(logh, LEV_ERROR, T_PRE, "Error in executing request!");
      vr.setError(ERR_ATTR_EMPTY, voname + " : no valid VOMS attributes found for your request.");
      return false;
    }

    if(subset) 
    {
      LOG(logh, LEV_WARN, T_PRE, "Only a subset of the requested attributes will be issued.");
      vr.setError(WARN_ATTR_SUBSET, voname + 
      " : your certificate already contains attributes, only a subset of them can be issued.");
    }
  }

  if (fqans.empty()) {

    vr.setError(ERR_NOT_MEMBER, std::string("You are not a member of the ") + voname + " VO!");
    return false;

  } else {

    std::vector<std::string>::const_iterator end = fqans.end();

    for (std::vector<std::string>::const_iterator i = fqans.begin(); i != end; ++i)
      LOGM(VARP, logh, LEV_INFO, T_PRE, "Issued FQAN: %s",  (*i).c_str());

    if (LogLevelMin(logh, LEV_INFO)) {
      if(result && !attribs.empty()) {
        std::vector<gattrib>::const_iterator end = attribs.end();
        for(std::vector<gattrib>::const_iterator i = attribs.begin(); i != end; ++i)
          LOGM(VARP, logh, LEV_INFO, T_PRE,  "Issued generic attribute: %s", i->str().c_str());
      }
      else
        LOGM(VARP, logh, LEV_DEBUG, T_PRE,  "No generic attributes found for user.");
    }

    std::string codedac;
    std::string data;

    if (comm[0] == "N") {

      std::vector<std::string>::const_iterator end = fqans.end();
      for (std::vector<std::string>::const_iterator i = fqans.begin(); i != end; ++i)
        data += (*i).c_str() + std::string("\n");

    } else {

      // This is the real AC encoding
      int res = 1;
      BIGNUM * serial = get_serial();

      if (!serial)
        LOG(logh, LEV_ERROR, T_PRE, "Can't get Serial Number!");
      else {
        /* Make AC */
        AC *a = AC_new();

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
          unsigned char *buf = NULL;

          int len = i2d_AC(a, &buf);

          if (len > 0) {
            codedac = std::string(reinterpret_cast<char*>(buf), len);
          }

          OPENSSL_free(buf);
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

    (void)SetCurLogType(logh, T_RESULT);

    vr.setAC(codedac);
    vr.setData(data);
    return true;
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
    throw voms_init_error("unable to read options");
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
    throw voms_init_error("can't read password file!");
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
        (**role) = '\0';
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

static long long get_userid(sqliface::interface *db, X509 *cert, const std::string& voname, vomsresult &vr)
{
  long long uid = -1;

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
