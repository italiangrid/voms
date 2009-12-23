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
#include "config.h"

extern "C" {
#include "replace.h"
#include "uuid.h"

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
#include "gssapi.h"
#include "credentials.h"

#include "log.h"
#include "streamers.h"
#include "sslutils.h"

static int reload = 0;

void *logh = NULL;
#include "myproxycertinfo.h"
}

#include "soapH.h"

#include "Server.h"

#include "VOMSServer.h"

#include "options.h"
#include "data.h"
#include "pass.h"
#include "errors.h"
#include "vomsxml.h"
#include "fqan.h"

extern "C" {
extern char *Decode(const char *, int, int *);
extern char *Encode(const char *, int, int *, int);
}

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

sqliface::interface *db = NULL;

typedef std::map<std::string, int> ordermap;

static ordermap ordering;

static std::string firstfqan="";

static std::string sqllib = "";

static std::string VOName="";
static char *maingroup = NULL;

typedef sqliface::interface* (*cdb)();
typedef int (*gv)();

cdb NewDB;
gv  getlibversion;
int default_validity = -1;

bool compat_flag = false;
bool short_flags = false;

int soap_port=8443;
static std::string soap_host = "";
static char *soap_hostname = NULL;
static bool checkinside(gattrib g, std::vector<std::string> list);

std::string
makeACSSL(SSL *ssl, void *logh, char **FQANs, int size, const std::string &order, char **targets, int targsize, int requested, VOMSServer *v);

std::string
makeACSOAP(struct soap *soap, void *logh, char **FQANs, int size, char **targets, int targsize, int requested, 
           VOMSServer *v);

int
makeACREST(struct soap *soap, void *logh, char **FQANs, int size, int requested, int unknown, VOMSServer *v);

std::string makeAC(EVP_PKEY *key, X509 *issuer, X509 *holder, 
                   const std::string &message, void *logh, VOMSServer *v);

int http_get(soap *soap);

static bool determine_group_and_role(std::string command, char *comm, char **group, char **role);

static int (*pw_cb)() = NULL;

static char *canonicalize_string(char *original);

static int pwstdin_callback(char * buf, int num, int w) {
  
  int i;
  
  if (!(fgets(buf, num, stdin))) {
    std::cerr << "Failed to read pass-phrase from stdin" << std::endl;
    return -1;
  }
  i = strlen(buf);
  if (buf[i-1] == '\n') {
      buf[i-1] = '\0';
      i--;
  }
  return i;	
  
}

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
static BIGNUM *get_serial();

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
    std::string fqan;

    if (divider == std::string::npos) {
      fqan = attribute;
      if (firstfqan.empty()) {
        firstfqan = fqan;
      }
    }
    else {
      fqan = attribute.substr(0, divider) +
        "/Role=" + attribute.substr(divider+1);

      if (firstfqan.empty())
        firstfqan = fqan;
    }

    LOGM(VARP, logh, LEV_DEBUG, T_PRE, "Order: %s",fqan.c_str());
    ordering.insert(std::make_pair<std::string, int>(fqan,order));
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

VOMSServer *selfpointer = NULL;

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
                                                 logf("%d:%h:%s[%p]: msg=\"%V:%T:%F (%f:%l):%m\""),
                                                 newformat(false),
                                                 insecure(false),
                                                 shortfqans(false),
                                                 do_syslog(false),
                                                 base64encoding(false),
                                                 nologfile(false)
{
  struct stat statbuf;
  selfpointer = this;

  signal(SIGCHLD, sigchld_handler);
  signal(SIGTERM, sigterm_handler);
  ac = argc;
  av = argv;

  if ((stat("/etc/nologin", &statbuf)) == 0)
    throw VOMSInitException("/etc/nologin present\n");

  InitProxyCertInfoExtension(1);

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
    {"contactstring",   1, (int *)&contactstring,     OPT_STRING},
    {"mysql-port",      1, (int *)&mysql_port,        OPT_NUM},
    {"mysql-socket",    1, (int *)&mysql_socket,      OPT_STRING},
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
    {"skipcacheck",     1, (int *)&insecure,          OPT_BOOL},
    {"shortfqans",      0, (int *)&shortfqans,        OPT_BOOL},
    {"syslog",          0, (int *)&do_syslog,         OPT_BOOL},
    {"base64",          0, (int *)&base64encoding,    OPT_BOOL},
    {"nologfile",       0, (int *)&nologfile,         OPT_BOOL},
//     {"soap_port",       1, &soap_port,                OPT_NUM},
//     {"soap_host",       1, (int *)&soap_host,         OPT_STRING},
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
            "[-logdateformat format] [-debug] [-backlog num] [-skipcacheck]\n"
            "[-version] [-sqlloc path] [-compat] [-logmax n] [-socktimeout n]\n"
            "[-shortfqans] [-newformat] [-syslog] [-base64] [-nologfile]\n");

  if (!getopts(argc, argv, opts))
    throw VOMSInitException("unable to read options");

  short_flags = shortfqans;
  default_validity = validity;
  VOName = voname;
  maingroup = (char *)malloc(strlen(voname.c_str())+2);
  maingroup = strcpy(maingroup, "/");
  maingroup = strcat(maingroup, voname.c_str());

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
    //    if ((logger = FileNameStreamerAdd(logh, logfile.c_str(), logmax, code, 0))) {
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
      //      (void)LogDateFormat(logh, logdf.c_str());
      (void)StartLogger(logh, code);
      if (!nologfile)
        (void)LogActivate(logh, "FILE");
      if (do_syslog)
        (void)LogActivate(logh, "SYSLOG");

      (void)LogOption(logh, "NAME", logfile.c_str());
      (void)LogOptionInt(logh, "MAXSIZE", logmax);
      (void)LogOption(logh, "DATEFORMAT", logdf.c_str());
      //    }
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
    LOGM(VARP, logh, LEV_ERROR, T_PRE, (std::string("Error connecting to the database : ") + errormessage).c_str());
    throw VOMSInitException((std::string("Error connecting to the database : ") + errormessage));
  }


  version = globus(version);
  if (version == 0) {
    std::cerr << "Unable to discover Globus Version: Trying for 2.2"
              << std::endl;
    LOG(logh, LEV_WARN, T_PRE, "Unable to discover Globus Version: Trying for 2.2");
    version = 22;
  }

  /* Determine hostname */
  int   ok;

  int   hostnamesize = 50;
  char *hostname = new char[1];
  do {
    delete[] hostname;
    hostname = new char[hostnamesize];
    ok = gethostname(hostname, hostnamesize);
    hostnamesize += 50;
  } while (ok);
  

  if (fakeuri.empty()) {
    std::string temp;

    uri = std::string(hostname) + ":" + stringify(daemon_port, temp);

  }
  else
    uri = fakeuri;

  if (soap_host.empty()) {
    soap_hostname = NULL;
  }
  else
    soap_hostname = strdup(hostname);

  delete[] hostname;

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

  sock.SetLogger(logh);
  std::string msg = "URI: " + uri;

  LOGM(VARP, logh, LEV_INFO, T_PRE, "URI: %s", uri.c_str());
  LOGM(VARP,  logh, LEV_INFO, T_PRE, "Detected Globus Version: %d", version);

  AC_Init();
}

VOMSServer::~VOMSServer() {}

static char *cacertdir = "/etc/grid-security/certificates";
static char *hostcert  = "/etc/grid-security/hostcert.pem";
static char *hostkey   = "/etc/grid-security/hostkey.pem";

extern proxy_verify_desc *setup_initializers(char*);

static int myverify_callback(int ok, X509_STORE_CTX *ctx)
{
  if (!X509_STORE_CTX_get_ex_data(ctx, PVD_STORE_EX_DATA_IDX)) {
    proxy_verify_desc *pvd = setup_initializers(cacertdir);
    pvd->pvxd->certdir = cacertdir;
    X509_STORE_CTX_set_ex_data(ctx, PVD_STORE_EX_DATA_IDX, pvd);
  }
  return proxy_verify_callback(ok, ctx);
}

static int (*old_plugin)(struct soap *);

static int myplugin(struct soap *soap)
{
  if (old_plugin(soap) == SOAP_OK) {
    X509 *cert = NULL;
    STACK_OF(X509) *chain = NULL;
    EVP_PKEY *upkey = NULL;
    pw_cb =(int (*)())(pwstdin_callback);

    if (!load_credentials(hostcert, hostkey, &cert, &chain, &upkey, pw_cb))
      return SOAP_ERR;

    SSL_CTX_set_verify(soap->ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, myverify_callback);
    SSL_CTX_use_certificate(soap->ctx, cert);
    SSL_CTX_use_PrivateKey(soap->ctx, upkey);
    SSL_CTX_set_purpose(soap->ctx, X509_PURPOSE_ANY);
    SSL_CTX_set_mode(soap->ctx, SSL_MODE_AUTO_RETRY);
    SSL_CTX_set_verify_depth(soap->ctx, 100);

    if (chain) {
      /*
       * Certificate was a proxy with a cert. chain.
       * Add the certificates one by one to the chain.
       */
      for (int i = 0; i <sk_X509_num(chain); ++i) {
        X509 *cert = (sk_X509_value(chain,i));

        if (!X509_STORE_add_cert(soap->ctx->cert_store, cert)) {
          if (ERR_GET_REASON(ERR_peek_error()) == X509_R_CERT_ALREADY_IN_HASH_TABLE) {
            ERR_clear_error();
            continue;
          }
          else {
            return SOAP_ERR;
          }
        }
      }
    }
    
    return SOAP_OK;
  }

  return SOAP_ERR;
}

void VOMSServer::Run()
{
  pid_t pid = 0;
  struct soap *sop = NULL;
  int m,s;

  if (!x509_user_cert.empty())
    hostcert = (char*)x509_user_cert.c_str();

  if (!x509_user_key.empty())
    hostkey = (char *)x509_user_key.c_str();

  if (!x509_cert_dir.empty())
    cacertdir = (char *)x509_cert_dir.c_str();

  if (!debug)
    if (daemon(0,0))
      exit(0);

  SetOwner(getpid());

  fd_set rset;
  FD_ZERO(&rset);

  sop = soap_new();
//   old_plugin = sop->fsslauth;
//  sop->fsslauth = myplugin;
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
        if (sock.Listen()) {
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

              LOGM(VARP, logh, LEV_INFO, T_PRE, "At: %s Received Contact :", timestamp().c_str());
              LOGM(VARP, logh, LEV_INFO, T_PRE, " user: %s", user.c_str());
              LOGM(VARP, logh, LEV_INFO, T_PRE, " ca  : %s", userca.c_str());
              LOGM(VARP, logh, LEV_INFO, T_PRE, " serial: %s", sock.peer_serial.c_str());
              std::string peek;

              (void)sock.Peek(3, peek);

              LOGM(VARP, logh, LEV_INFO, T_PRE, "peek data: %s", peek.c_str());

              if (peek == "GET") {
                sop->socket = sock.newsock;
                sop->ssl = sock.ssl;
                sop->fparse(sop);
                return;
              }
              LOG(logh, LEV_DEBUG, T_PRE, "Starting Execution.");
              Execute(sock.own_key, sock.own_cert, sock.peer_cert, sock.actual_cert);
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
      FD_ZERO(&rset);
      FD_SET(sock.sck, &rset);
    }
  }
  catch (...) {}
}

std::string makeAC(EVP_PKEY *key, X509 *issuer, X509 *holder, 
                   const std::string &message, void *logh, VOMSServer *v)
{
  LOGM(VARP, logh, LEV_DEBUG, T_PRE, "Received Request: %s", message.c_str());

  struct request r;

  if (!XML_Req_Decode(message, r)) {
    LOGM(VARP, logh, LEV_ERROR, T_PRE, "Unable to interpret command: %s",message.c_str());
    return false;
  }

  std::vector<std::string> comm = r.command;

  bool dobase64 = v->base64encoding | r.base64;
  int requested = r.lifetime;

  std::vector<std::string> targs;

  firstfqan = "";
  ordering.clear();

  parse_targets(r.targets, targs);

  std::vector<gattrib> attributes;
  std::string data = "";
  std::string tmp="";
  std::string command=comm[0];
  bool result = true;
  bool result2 = true;
  std::vector<errorp> errs;
  errorp err;

  /* Interpret user requests */

  if (requested != 0) {
    if (requested == -1)
      requested = v->validity;
    else if (v->validity < requested) {
      err.num = WARN_SHORT_VALIDITY;
      err.message = v->uri + ": The validity of this VOMS AC in your proxy is shortened to " +
        stringify(v->validity, tmp) + " seconds!";
      errs.push_back(err);
      requested = v->validity;
    }
  }

  std::vector<std::string> fqans;
  std::vector<gattrib> attribs;
  signed long int uid = -1;

  sqliface::interface *newdb = db->getSession();

  if (!newdb) {
    err.num = ERR_WITH_DB;
    err.message = v->voname + ": Problems in DB communication.";

    LOG(logh, LEV_ERROR, T_PRE, err.message.c_str());
    errs.push_back(err);
    return XML_Ans_Encode("A", errs, dobase64);
  }

  if (!newdb->operation(OPERATION_GET_USER, &uid, holder)) {
    int code;
    std::string message;
    LOG(logh, LEV_ERROR, T_PRE, "Error in executing request!");
    LOG(logh, LEV_ERROR, T_PRE, newdb->errorMessage());
    code = newdb->error();
    char *mes = newdb->errorMessage();
    if (mes) 
      message = std::string(mes);
    else
      message = "unknown";
  
    db->releaseSession(newdb);

    if (code == ERR_USER_SUSPENDED) {
      err.num = ERR_SUSPENDED;
      err.message = std::string("User is currently suspended!\nSuspension reason: ") + message;
    } else if (code != ERR_NO_DB) {
      err.num = ERR_NOT_MEMBER;
      err.message = v->voname + ": User unknown to this VO.";
    }
    else {
      err.num = ERR_WITH_DB;
      err.message = v->voname + ": Problems in DB communication.";
    }


    LOG(logh, LEV_ERROR, T_PRE, err.message.c_str());
    errs.push_back(err);
    return XML_Ans_Encode("A", errs, dobase64);
  }

  LOGM(VARP, logh, LEV_INFO, T_PRE, "Userid = \"%ld\"", uid);

  bool setuporder = false;

  if (r.order.empty())
    setuporder = true;

  int k = 0;

  for(std::vector<std::string>::iterator i = comm.begin(); i != comm.end(); ++i) {
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

        if (setuporder) {
          if (!r.order.empty())
            r.order += ",";
        r.order += std::string("/Role=") + role;
        }
        break;

      case 'G':
        if ((result = newdb->operation(OPERATION_GET_GROUPS, &fqans, uid))) {
          if (not_in(std::string(group), fqans))
            result = false;
          else
            result2 = newdb->operation(OPERATION_GET_GROUPS_ATTRIBS, &attribs, uid);
        }

        if (setuporder) {
          if (!r.order.empty())
            r.order += ",";
          r.order += group;
        }

        break;

      case 'B':
        if ((result = newdb->operation(OPERATION_GET_GROUPS_AND_ROLE, &fqans, uid, group, role)))
          result2 = newdb->operation(OPERATION_GET_GROUPS_AND_ROLE_ATTRIBS, &attribs, uid, group, role);
        result2 |= newdb->operation(OPERATION_GET_GROUPS_ATTRIBS, &attribs, uid);

        if (setuporder) {
          if (!r.order.empty())
            r.order += ",";
        r.order += group + std::string("/Role=") + role;
        }

        break;

      case 'N':
        result = newdb->operation(OPERATION_GET_ALL, &fqans, uid);
        break;

      default:
        result = false;
        LOGM(VARP, logh, LEV_ERROR, T_PRE, "Unknown Command \"%c\"", commletter);
        break;
      }
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

  LOGM(VARP, logh, LEV_DEBUG,T_PRE, "ordering: %s", r.order.c_str());

  parse_order(r.order, ordering);

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

  if (!result) {
    LOG(logh, LEV_ERROR, T_PRE, "Error in executing request!");
    err.num = ERR_NOT_MEMBER;
    if (command == (std::string("G/")+ v->voname))
      err.message = v->voname + ": User unknown to this VO.";
    else
      err.message = v->voname + ": Unable to satisfy " + command + " Request!";

    LOG(logh, LEV_ERROR, T_PRE, err.message.c_str());
    errs.push_back(err);
    return XML_Ans_Encode("A", errs, dobase64);
  }

  if (!firstfqan.empty()) {
    std::vector<std::string>::iterator i = fqans.begin();
    if (i != fqans.end()) {
      LOGM(VARP, logh, LEV_DEBUG, T_PRE,  "fq = %s", firstfqan.c_str());
      if (*i != firstfqan) {
        err.num = WARN_NO_FIRST_SELECT;
        err.message = "FQAN: " + *i + " is not the first selected!\n";
        errs.push_back(err);
      }
    }
  }


  if(!fqans.empty()) {
    /* check whether the user is allowed to requests those attributes */
    vomsdata vd("", "");
    vd.SetVerificationType((verify_type)(VERIFY_SIGN));
    vd.Retrieve(v->sock.actual_cert, v->sock.peer_stack, RECURSE_DEEP);

    /* find the attributes corresponding to the vo */
    std::vector<std::string> existing;
    for(std::vector<voms>::iterator index = (vd.data).begin(); index != (vd.data).end(); ++index) {
      if(index->voname == v->voname)
        existing.insert(existing.end(),
                     index->fqan.begin(),
                     index->fqan.end());
    }
  
    /* if attributes were found, only release an intersection beetween the requested and the owned */
    std::vector<std::string>::iterator end = fqans.end();
    bool subset = false;

    int oldsize = fqans.size();
    if (!existing.empty())
      if (fqans.erase(remove_if(fqans.begin(),
                                fqans.end(),
                                bind2nd(std::ptr_fun(not_in), existing)),
                      fqans.end()) != end)
        subset = true;

    if (subset) {
      // remove attributes for qualifier which had been removed
      attribs.erase(remove_if(attribs.begin(), attribs.end(),
                              bind2nd(ptr_fun(checkinside), fqans)),
                    attribs.end());
    }

    // Adjust for long/short format
    if (!short_flags && !fqans.empty()) {
      std::vector<std::string> newfqans(fqans);
      fqans.clear();
      std::vector<std::string>::iterator i = newfqans.begin();
      while (i != newfqans.end()) {
        std::string fqan = *i;
        LOGM(VARP, logh, LEV_DEBUG, T_PRE, "Initial FQAN: %s", fqan.c_str());
        if (fqan.find("/Role=") != std::string::npos)
          fqan += "/Capability=NULL";
        else
          fqan += "/Role=NULL/Capability=NULL";
        LOGM(VARP, logh, LEV_DEBUG, T_PRE, "Processed FQAN: %s", fqan.c_str());
        fqans.push_back(fqan);
        i++;
      }
    }

    // no attributes can be send
    if (fqans.empty()) {
      LOG(logh, LEV_ERROR, T_PRE, "Error in executing request!");
      err.num = ERR_ATTR_EMPTY;
      err.message = v->voname + " : your certificate already contains attributes, only a subset of them can be issued.";
      errs.push_back(err);
      return XML_Ans_Encode("A", errs, dobase64);
    }

    // some attributes can't be send
    if(subset) {
      LOG(logh, LEV_ERROR, T_PRE, "Error in executing request!");
      err.num = WARN_ATTR_SUBSET;
      err.message = v->voname + " : your certificate already contains attributes, only a subset of them can be issued.";
      errs.push_back(err);
    }
  }

  if (!fqans.empty()) {
    // test logging retrieved attributes

    if(result && !attributes.empty()) {
      for(std::vector<gattrib>::iterator i = attributes.begin(); i != attributes.end(); ++i)
        LOGM(VARP, logh, LEV_DEBUG, T_PRE,  "User got attributes: %s", i->str().c_str());
    }
    else
      LOGM(VARP, logh, LEV_DEBUG, T_PRE,  "User got no attributes or something went wrong searching for them.");
  
    std::vector<std::string> attributes_compact;
    for(std::vector<gattrib>::iterator i = attribs.begin(); i != attribs.end(); ++i)
      attributes_compact.push_back(i->str());

    ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

    BIGNUM * serial = get_serial();

    int res = 1;
    std::string codedac;

    if (comm[0] != "N") {
      if (!serial)
        LOG(logh, LEV_ERROR, T_PRE, "Can't get Serial Number!");

      if (serial) {
        AC *a = AC_new();

        LOGM(VARP, logh, LEV_DEBUG, T_PRE, "length = %d", i2d_AC(a, NULL));
        if (a)
          res = createac(issuer, v->sock.own_stack, holder, key, serial,
                         fqans, targs, attributes_compact, &a, v->voname, v->uri, requested, !v->newformat);

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
        else {
          err.num = ERR_NOT_MEMBER;
          err.message = std::string(get_error(res));
          errs.push_back(err);
        }
        AC_free(a);
      }

      if (res || codedac.empty()) {
        LOG(logh, LEV_ERROR, T_PRE, "Error in executing request!");
        err.message = v->voname + ": Unable to satisfy " + command + " request due to database error.";
        errs.push_back(err);
        BN_free(serial);
        return XML_Ans_Encode("A", errs, dobase64);
      }
    }

    BN_free(serial);
    serial = NULL;
    (void)SetCurLogType(logh, T_RESULT);

    if (comm[0] == "N")
      data = "";

    for (std::vector<std::string>::iterator i = fqans.begin(); i != fqans.end(); i++) {
      LOGM(VARP, logh, LEV_INFO, T_PRE, "Request Result: %s",  (*i).c_str());
      if (comm[0] == "N")
        data += (*i).c_str() + std::string("\n");
    }

    return XML_Ans_Encode(codedac, data, errs, dobase64);
  }
  else if (!data.empty()) {
    return XML_Ans_Encode("", data, errs, dobase64);
  }
  else {
    err.num = ERR_NOT_MEMBER;
    err.message = std::string("You are not a member of the ") + v->voname + " VO!";
    errs.push_back(err);
    return XML_Ans_Encode("", errs, dobase64);
  }
}

void
VOMSServer::Execute(EVP_PKEY *key, X509 *issuer, X509 *holder, X509 *peer_cert)
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

  std::string answer = makeAC(key, issuer, holder, message, logh, this);
  LOGM(VARP, logh, LEV_DEBUG, T_PRE, "Sending: %s", answer.c_str());
  sock.Send(answer);
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
    {"mysql-port",      1, (int *)&mysql_port,        OPT_NUM},
    {"mysql-socket",    1, (int *)&mysql_socket,      OPT_STRING},
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
    {"compat",          0, (int *)&compat_flag,       OPT_BOOL},
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

  short_flags = shortfqans;

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
    if (debug)
      lev = LEV_DEBUG;
    (void)LogLevel(logh, lev);

    if (lev == LEV_DEBUG)
      logt = T_STARTUP|T_REQUEST|T_RESULT;


    (void)LogType(logh, logt);
    (void)SetCurLogType(logh, T_STARTUP);
    (void)LogService(logh, "vomsd");
    (void)LogFormat(logh, logf.c_str());
    //    (void)LogDateFormat(logh, logdf.c_str());
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
        *group = string;
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
        *group = string;
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


static bool checkinside(gattrib g, std::vector<std::string> list) {
  return !g.qualifier.empty() && (find(list.begin(), list.end(), g.qualifier) == list.end());
}

int ns3__getInterfaceVersion(struct soap *soap, char **tmp_string)
{
  *tmp_string="4";
  return SOAP_OK;
}

int ns3__getVersion(struct soap *soap, char **tmp_string)
{
  *tmp_string="2.0";
  return SOAP_OK;
}

SOAP_NMAC struct Namespace namespaces[] =
{
	{"SOAP-ENV", "http://schemas.xmlsoap.org/soap/envelope/", "http://www.w3.org/*/soap-envelope", NULL},
	{"SOAP-ENC", "http://schemas.xmlsoap.org/soap/encoding/", "http://www.w3.org/*/soap-encoding", NULL},
	{"xsi", "http://www.w3.org/2001/XMLSchema-instance", "http://www.w3.org/*/XMLSchema-instance", NULL},
	{"xsd", "http://www.w3.org/2001/XMLSchema", "http://www.w3.org/*/XMLSchema", NULL},
	{"ns1", "http://www.example.org/voms/", NULL, NULL},
	{NULL, NULL, NULL, NULL}
};

int my_receiver_fault(struct soap *soap, const char *msg)
{
  return soap_receiver_fault(soap, msg, msg);
}


int __ns1__GetAttributeCertificate(struct soap *soap, 
    struct _ns1__GetAttributeCertificate *req,
    struct _ns1__GetAttributeCertificateResponse *ans)
{
  char *message=NULL;

  struct ns1__StatusType *st = (struct ns1__StatusType*)
    malloc(sizeof(struct ns1__StatusType));

  if (!st)
    return my_receiver_fault(soap, "Not Enough Memory");

  st->ns1__StatusCode = (struct ns1__StatusCodeType *)
    malloc(sizeof(struct ns1__StatusCodeType));

  if (!st->ns1__StatusCode)
    return my_receiver_fault(soap, "Not Enough Memory");

  std::string answerstring = makeACSOAP(soap, logh, 
                                        req->ns1__FQAN, req->__sizeFQAN,
                                        req->ns1__Target, req->__sizeTarget,
                                        *req->ns1__Lifetime, selfpointer);

  st->ns1__StatusCode->Value="http://voms.cnaf.infn.it";
  st->ns1__StatusMessage = message;
  ans->Status = st;

  ans->AttributeCertificate="";
  answer a;

  if (XML_Ans_Decode(answerstring, a)) {
    if (!a.ac.empty()) {
      ans->AttributeCertificate = (char *)a.ac.c_str();
    }
  }

  return SOAP_OK;
}

                                   
std::string
makeACSOAP(struct soap *soap, void *logh, 
           char **FQANs, int size, 
           char **targets, int targsize, 
           int requested, VOMSServer *v)
{
  return makeACSSL(soap->ssl, logh, FQANs, size, 
                   std::string(""), targets, 
                   targsize, requested, selfpointer);
}

std::string
makeACSSL(SSL *ssl, void *logh, char **FQANs, int size, const std::string &origorder, char **targets, int targsize, int requested, VOMSServer *v)
{
  X509 *holder = SSL_get_peer_certificate(ssl);
  X509 *issuer = NULL;
  STACK_OF(X509) *own_stack = NULL;
  EVP_PKEY *key = NULL;
  pw_cb =(int (*)())(pwstdin_callback);
  char *hostcert = "/etc/grid-security/hostcert.pem";
  char *hostkey  = "/etc/grid-security/hostkey.pem";

  if (!v->x509_user_cert.empty())
    hostcert = (char*)v->x509_user_cert.c_str();

  if (!v->x509_user_key.empty())
    hostkey = (char *)v->x509_user_key.c_str();

  if (!load_credentials(hostcert, hostkey, 
                        &issuer, NULL,  &key, pw_cb)) {
    X509_free(issuer);
    EVP_PKEY_free(key);
    return "";
  }

  std::string command = "";

  int i = 0;
  while (i < size) {
    if (i != 0)
      command +=",";

    command += FQANParse(FQANs[i]);

    i++;
  }


  std::string targs = "";

  i = 0;
  while (i <targsize) {
    if (i != 0)
      targs += ",";
    targs += std::string(targets[i]);
    i++;
  }

  std::string message = XML_Req_Encode(command, std::string(""), targs, requested);

  std::string ret = makeAC(key, issuer, holder, message, logh, selfpointer);
  X509_free(issuer);
  EVP_PKEY_free(key);

  return ret;
}

int http_get(soap *soap)
{
  char *path = strdup(soap->path);
  int unknown = 0;

  LOGM(VARP, logh, LEV_DEBUG, T_PRE, "REST Request: %s", path);

  if (!path)
    return SOAP_GET_METHOD;

  char *s = strchr(path, '?');

  if (s)
    *s='\0';

  char *prepath=canonicalize_string(path);

  if (strcmp(prepath, "/generate-ac") != 0) {
    soap_response(soap,404);
    soap_end_send(soap);
    return 404;
  }

  soap_response(soap, SOAP_HTML);

  /* determine parameters */
  std::vector<std::string> fqans;
  int lifetime = -1;
  std::string orderstring;
  int size = 0;

  if (s) {
    ++s;

    if (!strlen(s)) {
      free(path);
      soap_response(soap, 404);
      soap_end_send(soap);
      return 500;
    }

    char *basis = s;
    char *next = NULL;

    do {
      next = strchr(basis, '&');

      if (next)
        *next='\0';

      char *equal = strchr(basis, '=');
      if (!equal)
        return 500;
      *equal='\0';

      char *name   = basis;
      char *value  = equal+1;
      char *cname  = canonicalize_string(name);
      char *cvalue = canonicalize_string(value);

      if (strcmp(cname, "lifetime") == 0)
        lifetime = atoi(cvalue);

      else if (strcmp(cname, "fqans") == 0) {
        char *position = strchr(cvalue, ',');

        while (position) {
          *position = '\0';
          fqans.push_back(std::string(cvalue));
          cvalue = ++position;
          position = strchr(cvalue, ',');
	  size ++;
        }
        fqans.push_back(std::string(cvalue));

        size++;
      }

      else if (strcmp(cname, "order") == 0) {
        if (orderstring.empty())
          orderstring = std::string(cvalue);
        else
          orderstring += ", " + std::string(cvalue);
      }
      else {
	/* purposefully ignore other parameters */
	/* but put it in an otherwise positive response */
	unknown = 1;
      }
      if (next)
        basis = next+1;
    } while (next);
  }

  char **FQANS = NULL;
  if (size) {
    FQANS = (char**)malloc(sizeof(char*)*size);

    for (int i = 0; i < size; i++)
      FQANS[i] = (char*)(fqans[i].c_str());
  }
  else {
    FQANS = (char**)malloc(sizeof(char*));
    FQANS[0]=maingroup;
    size = 1;
  }
  int res = makeACREST(soap, logh, FQANS, size, lifetime, unknown, selfpointer);

  int i =0;

  free(FQANS);

  free(path);

  return res;
}

static int hexint(char c)
{
  if (c >= '0' && c <= '9')
    return c - '0';

  if (c >= 'a' && c <= 'f')
    return c - 'a' + 10;

  if (c >= 'A' && c <= 'F')
    return c - 'A' + 10;

  return 0;
}

static char *canonicalize_string(char *original)
{
  char *currentin  = original;
  char *currentout = original;

  while (*currentin != '\0') {
    if (*currentin != '%')
      *currentout++ = *currentin++;
    else {
      char first = *(currentin+1);

      if (first != '\0') {
        char second = *(currentin+2);

        if (second != '\0') {
          if (isxdigit(first) && isxdigit(second)) {
            *currentout++=hexint(first)*16 + hexint(second);
            currentin += 3;
          }
          else
            *currentout++ = *currentin++;
        }
        else
          *currentout++ = *currentin++;
      }
      else
        *currentout++ = *currentin++;
    }
  }
  *currentout='\0';

  return original;
}

static int EncodeAnswerForRest(const std::string& input, int unknown, std::string& output);

int
makeACREST(struct soap *soap, void *logh, char **FQANs, int size, int requested, int unknown, VOMSServer *v)
{
  AC *ac = NULL;
  char *message = NULL;
  char *targets = NULL;

  std::string result = makeACSSL(soap->ssl, logh, FQANs, size, std::string(""), &targets, 0, requested, selfpointer);

  std::string output;

  int value = EncodeAnswerForRest(result, unknown, output);
  soap->http_content = "text/xml";
  soap_response(soap, value);
  soap_send(soap, output.c_str());
  soap_end_send(soap);

  return SOAP_OK;
}

static int EncodeAnswerForRest(const std::string& input, int unknown, std::string& output)
{
  answer a;

  if (XML_Ans_Decode(input, a)) {
    if (!a.ac.empty() && a.ac != "A") {
      int len = 0;
      char *ac = Encode(a.ac.c_str(), a.ac.length(), &len, !a.base64);

      output = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><voms><ac>" +std::string(ac, len) +"</ac>";
      std::vector<errorp> errs = a.errs;
      for (std::vector<errorp>::iterator i = errs.begin(); i != errs.end(); i++)
        output +="<warning>"+i->message+"</warning>";
      if (unknown) 
	output +="<warning>Unknown parameters in the request were ignored!</warning>";
      output += "</voms>";
      free(ac);
      return SOAP_HTML;
    }
    else {
      // some error occured.  Look inside
      output = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><voms><error>";
      std::vector<errorp> errs = a.errs;
      int value = 500;

      for (std::vector<errorp>::iterator i = errs.begin(); i != errs.end(); i++) {
        if (i->num == ERR_NOT_MEMBER) {
          const char *msg = i->message.c_str();

          if (strstr(msg, "Unable to satisfy") == NULL) {
            output += "<code>NoSuchUser</code><message>" +
              i->message + "</message>";
            value = 403;
          }
          else {
            output += "<code>BadRequest</code><message>"+i->message + "</message>";
            value = 400;
          }
        }
        else if (i->num == ERR_SUSPENDED) {
          const char *msg = i->message.c_str();
          value = 403;
          output +="<code>SuspendedUser</code><message>"+i->message+"</message>";
        }
      }
      output +="</error></voms>";
      return value;
    }
  }
  else {
      output = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><voms><error>"
        "<code>InternalError</code><message>Internal Error</message></voms>";
      return 500;
  }
}
