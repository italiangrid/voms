/*********************************************************************
 *
 * Authors: Vincenzo Ciaschini - Vincenzo.Ciaschini@cnaf.infn.it 
 *          Valerio Venturi - Valerio.Venturi@cnaf.infn.it 
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
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <stdlib.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <errno.h>

#include "listfunc.h"
#include "credentials.h"

#include "replace.h"
}
#include <iostream>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <string>

#include "options.h"
#include "vomsxml.h"


#include <voms_api.h>

#include "vomsclient.h"
#include "fqan.h"
#include "contact.hpp"


extern "C" 
{
#include "myproxycertinfo.h"
#include "vomsproxy.h"
}

#include "init.h"

static AC *getAC(const std::string& data);

const std::string SUBPACKAGE      = "voms-proxy-init";

/* use name specific to each distribution (defined in configure.in) */

std::string location;
std::string CONFILENAME;
std::string USERCONFILENAME;

/* global variable for output control */

bool debug = false;
bool quiet = false;

extern "C" {
  
static int (*pw_cb)() = NULL;


static int pwstdin_callback(char * buf, int num, UNUSED(int w)) 
{
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
  
static int kpcallback(int p, UNUSED(int n)) 
{
  char c='B';
    
  if (quiet) return 0;
    
  if (p == 0) c='.';
  if (p == 1) c='+';
  if (p == 2) c='*';
  if (p == 3) c='\n';
  if (!debug) c = '.';
  fputc(c,stderr);

  return 0;
}
  
extern int proxy_verify_cert_chain(X509 * ucert, STACK_OF(X509) * cert_chain, proxy_verify_desc * pvd);
extern void proxy_verify_ctx_init(proxy_verify_ctx_desc * pvxd);
}


class rand_wrapper 
{

public:
  
  rand_wrapper(unsigned int seed)
  {
    srand(seed);
  }

  UNUSED(ptrdiff_t operator() (ptrdiff_t max))
  {
    return static_cast<ptrdiff_t>(rand() % max);
  }

};

Client::Client(int argc, char ** argv) :
                                         ignorewarn(false),
                                         failonwarn(false),
                                         cacertfile(NULL),
                                         certdir(NULL),
                                         certfile(NULL),
                                         keyfile(NULL),
                                         confile(CONFILENAME),
                                         userconf(""),
                                         incfile(""),
                                         separate(""),
                                         bits(1024),
                                         hours(12),
                                         minutes(0),
                                         ac_hours(12),
                                         ac_minutes(0),
                                         limit_proxy(false),
                                         proxyver(0),
                                         pathlength(-1),
                                         verify(false),
                                         noregen(false),
                                         version(0),
#ifdef CLASS_ADD
                                         class_add_buf(NULL),
                                         class_add_buf_len(0),
#endif 
                                         dataorder(NULL),
                                         aclist(NULL),
                                         voID(""),
                                         listing(false),
                                         cert_chain(NULL),
                                         ucert(NULL),
                                         private_key(NULL),
                                         timeout(-1),
					 acfile(""),
                                         v(NULL)
{
  bool progversion = false;
  std::string valid;
  std::string vomslife;
  std::string certdir;
  std::string certfile;
  std::string keyfile;
  std::string outfile;
  std::vector<std::string> order;
  std::vector<std::string> targets;
  bool rfc = false;
  bool old = false;
  bool pwstdin = false;

  location = (getenv(LOCATION_ENV) ? getenv(LOCATION_ENV) : LOCATION_DIR);
  CONFILENAME     = (location + "/etc/vomses");
  USERCONFILENAME = std::string(USER_DIR) + std::string("/vomses");

  if (strrchr(argv[0],'/'))
    program = strrchr(argv[0],'/') + 1;
  else
    program = argv[0];

  if ((strcmp(program.c_str(), "voms-proxy-list") == 0) || (strcmp(program.c_str(), "edg-voms-proxy-list") == 0))
    listing = true;
  
  /* usage message */

  static const char *LONG_USAGE = NULL;

  if (!listing) {
    LONG_USAGE = \
      "\n" \
      "    Options\n" \
      "    -help, -usage                  Displays usage\n" \
      "    -version                       Displays version\n" \
      "    -debug                         Enables extra debug output\n" \
      "    -quiet, -q                     Quiet mode, minimal output\n" \
      "    -verify                        Verifies certificate to make proxy for\n" \
      "    -pwstdin                       Allows passphrase from stdin\n" \
      "    -limited                       Creates a limited proxy\n" \
      "    -valid <h:m>                   Proxy and AC are valid for h hours and m minutes\n" \
      "                                   (defaults to 12:00)\n" \
      "    -hours H                       Proxy is valid for H hours (default:12)\n" \
      "    -bits                          Number of bits in key {512|1024|2048|4096}\n" \
      "    -cert     <certfile>           Non-standard location of user certificate\n" \
      "    -key      <keyfile>            Non-standard location of user key\n" \
      "    -certdir  <certdir>            Non-standard location of trusted cert dir\n" \
      "    -out      <proxyfile>          Non-standard location of new proxy cert\n" \
      "    -voms <voms<:command>>         Specify voms server. :command is optional,\n" \
      "                                   and is used to ask for specific attributes\n" \
      "                                   (e.g: roles)\n" \
      "    -order <group<:role>>          Specify ordering of attributes.\n" \
      "    -target <hostname>             Targets the AC against a specific hostname.\n" \
      "    -vomslife <h:m>                Try to get a VOMS pseudocert valid for h hours\n" \
      "                                   and m minutes (default to value of -valid).\n" \
      "    -include <file>                Include the contents of the specified file.\n" \
      "    -conf <file>                   Read options from <file>.\n" \
      "    -confile <file>                Non-standard location of voms server addresses. Deprecated\n" \
      "    -userconf <file>               Non-standard location of user-defined voms server addresses. Deprecated\n" \
      "    -vomses <file>                 Non-standard location of configuration files.\n"
      "    -policy <policyfile>           File containing policy to store in the ProxyCertInfo extension.\n" \
      "    -pl, -policy-language <oid>    OID string for the policy language.\n" \
      "    -policy-language <oid>         OID string for the policy language.\n" \
      "    -path-length <l>               Allow a chain of at most l proxies to be generated from this ones.\n" \
      "    -globus <version>              Globus version. (MajorMinor)\n" \
      "    -proxyver                      Version of proxy certificate.\n" \
      "    -noregen                       Use existing proxy certificate to connect to server and sign the new proxy.\n" \
      "    -separate <file>               Saves the informations returned by the server on file <file>.\n" \
      "    -ignorewarn                    Ignore warnings.\n" \
      "    -failonwarn                    Treat warnings as errors.\n" \
      "    -list                          Show all available attributes.\n" \
      "    -rfc                           Creates RFC 3820 compliant proxy (synonymous with -proxyver 4)\n" \
      "    -old                           Creates GT2 compliant proxy (synonymous with -proxyver 2)\n" \
      "    -timeout <num>                 Timeout for server connections, in seconds.\n"
      "    -includeac <file>              get AC from file.\n"
      "\n";

    set_usage(LONG_USAGE);

    /* parse command-line option */

    struct option opts[] = {
      {"help",            0, NULL,                OPT_HELP},
      {"usage",           0, NULL,                OPT_HELP},
      {"version",         0, (int *)&progversion, OPT_BOOL},
      {"cert",            1, (int *)&certfile,    OPT_STRING},
      {"certdir",         1, (int *)&certdir,     OPT_STRING},
      {"out",             1, (int *)&outfile,     OPT_STRING},
      {"key",             1, (int *)&keyfile,     OPT_STRING},
      {"include",         1, (int *)&incfile,     OPT_STRING},
      {"hours",           1,        &hours,       OPT_NUM},
      {"valid",           1, (int *)&valid,       OPT_STRING},
      {"vomslife",        1, (int *)&vomslife,    OPT_STRING},
      {"bits",            1,        &bits,        OPT_NUM},
      {"debug",           0, (int *)&debug,       OPT_BOOL},
      {"limited",         0, (int *)&limit_proxy, OPT_BOOL},
      {"verify",          0, (int *)&verify,      OPT_BOOL},
      {"q",               0, (int *)&quiet,       OPT_BOOL},
      {"quiet",           0, (int *)&quiet,       OPT_BOOL},
      {"pwstdin",         0, (int *)&pwstdin,     OPT_BOOL},
      {"conf",            1, NULL,                OPT_CONFIG},
      {"confile",         1, (int *)&confile,     OPT_STRING},
      {"userconf",        1, (int *)&userconf,    OPT_STRING},
      {"vomses",          1, (int *)&confiles,    OPT_MULTI},
      {"voms",            1, (int *)&vomses,      OPT_MULTI},
      {"order",           1, (int *)&order,       OPT_MULTI},
      {"target",          1, (int *)&targets,     OPT_MULTI},
      {"globus",          1,        &version,     OPT_NUM},
      {"proxyver",        1,        &proxyver,    OPT_NUM},
      {"policy",          1, (int *)&policyfile,  OPT_STRING},
      {"policy-language", 1, (int *)&policylang,  OPT_STRING},
      {"pl",              1, (int *)&policylang,  OPT_STRING},
      {"path-length",     1,        &pathlength,  OPT_NUM},
      {"noregen",         0, (int *)&noregen,     OPT_BOOL},
      {"separate",        1, (int *)&separate,    OPT_STRING},
      {"ignorewarn",      0, (int *)&ignorewarn,  OPT_BOOL},
      {"failonwarn",      0, (int *)&failonwarn,  OPT_BOOL},
      {"list",            0, (int *)&listing,     OPT_BOOL},
      {"rfc",             0, (int *)&rfc,         OPT_BOOL},
      {"old",             0, (int *)&old,         OPT_BOOL},
#ifdef CLASS_ADD
      {"classadd",        1, (int *)class_add_buf,OPT_STRING},
#endif
      {"timeout",         1,        &timeout,     OPT_NUM},
      {"includeac",       1, (int *)&acfile,      OPT_STRING},
      {0, 0, 0, 0}
    };

    if (!getopts(argc, argv, opts))
      exit(1);

    if (!progversion && listing && vomses.size() != 1) {
      Print(ERROR) << "Exactly ONE voms server must be specified!\n" << std::endl;
      exit(1);
    }
  }
  else { /* listing mode */
    LONG_USAGE = \
      "\n" \
      "    Options\n" \
      "    -help, -usage                  Displays usage\n" \
      "    -version                       Displays version\n" \
      "    -debug                         Enables extra debug output\n" \
      "    -quiet, -q                     Quiet mode, minimal output\n" \
      "    -pwstdin                       Allows passphrase from stdin\n" \
      "    -cert     <certfile>           Non-standard location of user certificate\n" \
      "    -key      <keyfile>            Non-standard location of user key\n" \
      "    -certdir  <certdir>            Non-standard location of trusted cert dir\n" \
      "    -out      <proxyfile>          Non-standard location of new proxy cert\n" \
      "    -voms <voms<:command>>         Specify voms server. :command is optional,\n" \
      "                                   and is used to ask for specific attributes\n" \
      "                                   (e.g: roles)\n" \
      "    -include <file>                Include the contents of the specified file.\n" \
      "    -conf <file>                   Read options from <file>.\n" \
      "    -confile <file>                Non-standard location of voms server addresses.\n" \
      "    -userconf <file>               Non-standard location of user-defined voms server addresses.\n" \
      "    -vomses <file>                 Non-standard loation of configuration files.\n"
      "    -globus                        Globus version.\n" \
      "    -noregen                       Use existing proxy certificate to connect to server and sign the new proxy.\n" \
      "    -ignorewarn                    Ignore warnings.\n" \
      "    -failonwarn                    Treat warnings as errors.\n" \
      "    -timeout <num>                 Timeout for server connections, in seconds.\n" \
      "    -list                          Show all available attributes.\n" \
      "\n";

    set_usage(LONG_USAGE);

    /* parse command-line option */

    struct option opts[] = {
      {"help",            0, NULL,                OPT_HELP},
      {"usage",           0, NULL,                OPT_HELP},
      {"version",         0, (int *)&progversion, OPT_BOOL},
      {"cert",            1, (int *)&certfile,    OPT_STRING},
      {"certdir",         1, (int *)&certdir,     OPT_STRING},
      {"out",             1, (int *)&outfile,     OPT_STRING},
      {"key",             1, (int *)&keyfile,     OPT_STRING},
      {"debug",           0, (int *)&debug,       OPT_BOOL},
      {"verify",          0, (int *)&verify,      OPT_BOOL},
      {"q",               0, (int *)&quiet,       OPT_BOOL},
      {"quiet",           0, (int *)&quiet,       OPT_BOOL},
      {"pwstdin",         0, (int *)&pwstdin,     OPT_BOOL},
      {"conf",            1, NULL,                OPT_CONFIG},
      {"confile",         1, (int *)&confile,     OPT_STRING},
      {"userconf",        1, (int *)&userconf,    OPT_STRING},
      {"vomses",          1, (int *)&confiles,    OPT_MULTI},
      {"voms",            1, (int *)&vomses,      OPT_MULTI},
      {"globus",          1,        &version,     OPT_NUM},
      {"noregen",         0, (int *)&noregen,     OPT_BOOL},
      {"ignorewarn",      0, (int *)&ignorewarn,  OPT_BOOL},
      {"failonwarn",      0, (int *)&failonwarn,  OPT_BOOL},
      {"list",            0, (int *)&listing,     OPT_BOOL},
      {"timeout",         0,        &timeout,     OPT_NUM},
      {0, 0, 0, 0}
    };

    if (!getopts(argc, argv, opts))
      exit(1);

    if (!progversion && vomses.size() != 1) {
      Print(ERROR) << "Exactly ONE voms server must be specified!\n" << std::endl;
      exit(1);
    }
  }
  
  /* wouldn't make sense */

  if (debug)
    ignorewarn = failonwarn = quiet = false;

  if (quiet)
    ignorewarn = true;

  if (failonwarn)
    ignorewarn = false;

  /* show version and exit */
  
  if (progversion) {
    Print(FORCED) << SUBPACKAGE << "\nVersion: " << VERSION << std::endl;
    Print(FORCED) << "Compiled: " << __DATE__ << " " << __TIME__ << std::endl;
    exit(0);
  }

  /* set globus version */

  version = globus(version);
  if (version == 0) {
    version = 24;
    Print(DEBUG) << "Unable to discover Globus version: trying for 2.4" << std::endl;
  }
  else 
    Print(DEBUG) << "Detected Globus version: " << version/10 << "." << version % 10 << std::endl;
  
  /* set proxy version */
  if (rfc)
    proxyver = 4;

  if (old)
    proxyver = 2;

  if (proxyver!=2 && proxyver!=3 && proxyver != 4 && proxyver!=0) {
    Print(ERROR) << "Error: proxyver must be 2, 3 or 4" << std::endl;
    exit(1);
  }
  else if (proxyver==0) {
    if (version<30)
      proxyver = 2;
    else if (version < 40)
      proxyver = 3;
    else
      proxyver = 4;

    Print(DEBUG) << "Unspecified proxy version, settling on Globus version: " 
                 << proxyver << std::endl;
  }
  
  /* PCI extension option */ 
  
  if (proxyver >= 3) {
    if (!policylang.empty())
      if (policyfile.empty()) {
        Print(ERROR) << "Error: if you specify a policy language you also need to specify a policy file" << std::endl;
        exit(1);
      }
  }
  
  if (proxyver >= 3) {
    Print(DEBUG) << "PCI extension info: " << std::endl << " Path length: " << pathlength << std::endl;

    if (policylang.empty())
      Print(DEBUG) << " Policy language not specified." << policylang << std::endl;
    else
      Print(DEBUG) << " Policy language: " << policylang << std::endl;

    if (policyfile.empty())
      Print(DEBUG) << " Policy file not specified." << std::endl;
    else
      Print(DEBUG) << " Policy file: " << policyfile << std::endl;
  }
  
  /* get vo */
  
  char *vo = getenv("VO");
  if (vo != NULL && strcmp(vo, "") != 0)
    voID = vo;
  
  /* controls that number of bits for the key is appropiate */
  
  if ((bits!=512) && (bits!=1024) && (bits!=2048) && (bits!=4096)) {
    Print(ERROR) << "Error: number of bits in key must be one of 512, 1024, 2048, 4096." << std::endl;
    exit(1);
  }

  Print(DEBUG) << "Number of bits in key :" << bits << std::endl; 
  
  /* parse valid options */

  if (!valid.empty()) {
    std::string::size_type pos = valid.find(':');
    if (pos != std::string::npos && pos > 0) {
      hours  = ac_hours = atoi(valid.substr(0, pos).c_str());
      minutes = ac_minutes = atoi(valid.substr(pos+1).c_str());
    }
    else {
      Print(ERROR) << "-valid argument must be in the format: h:m" << std::endl;
      exit(1);
    }
    if (hours < 0) {
      Print(ERROR) << "-valid argument must be in the format: h:m" << std::endl;
      exit(1);
    }    
    if (minutes < 0 || minutes > 59) {
      Print(ERROR) << "specified minutes must be in the range 0-59" << std::endl;
      exit(1);
    }
  }

  /* parse vomslife options */

  if (!vomslife.empty()) {
    std::string::size_type pos = vomslife.find(':');

    if (pos != std::string::npos && pos > 0) {
      ac_hours   = atoi(vomslife.substr(0, pos).c_str());
      ac_minutes = atoi(vomslife.substr(pos+1).c_str());
    }
    else {
      Print(ERROR) << "-vomslife argument must be in the format: h:m" << std::endl;
      exit(1);
    }

    if (ac_hours < 0) {
      Print(ERROR) << "specified hours must be in the range 0-23" << std::endl;
      exit(1);
    }    

    if (ac_minutes < 0 || ac_minutes >59) {
      Print(ERROR) << "specified minutes must be in the range 0-59" << std::endl;
      exit(1);
    }
  }

  /* allow password from stdin */
  
  if (pwstdin)
    pw_cb = (int (*)())(pwstdin_callback);


  /* file used */
  
  this->cacertfile = NULL;
  this->certdir = (certdir.empty() ? NULL : strdup(const_cast<char *>(certdir.c_str())));
  this->outfile = (outfile.empty() ? NULL : strdup(const_cast<char *>(outfile.c_str())));
  this->certfile = (certfile.empty() ? NULL : strdup(const_cast<char *>(certfile.c_str())));
  this->keyfile = (keyfile.empty() ? NULL : strdup(const_cast<char *>(keyfile.c_str())));

  /* prepare proxy_cred_desc */

  if (!pcdInit())
    exit(3);

  v = new vomsdata("", certdir);

  /* Do VOMS-specific tests only if (at least) a voms server needs
     to be contacted (aside from simple parsing for correctness) */
  if (!vomses.empty()) {
    /* configuration files */

    if (userconf.empty()) {
      char *uc = getenv("VOMS_USERCONF");
      if (uc) {
        userconf = uc;
        confiles.push_back(userconf);
      }
    }

    /* If userconf is still empty, then VOMS_USERCONF
       was not defined */
    if (userconf.empty()) {
      char *uc = getenv("HOME");
      if (uc)
        userconf = std::string(uc) + "/" + USERCONFILENAME;
      else
        userconf = std::string("~/") + USERCONFILENAME;
    }
  
    /* parse order and target vector to a comma-separated list */
  
    for (std::vector<std::string>::iterator i = order.begin(); i != order.end(); i++)
      ordering += (i == order.begin() ? std::string("") : std::string(",")) + FQANParse(*i).substr(1);

    for (std::vector<std::string>::iterator i = targets.begin(); i != targets.end(); i++)
      targetlist += (i == targets.begin() ? ("") : std::string(",")) + *i;
  
    /* preliminary checks if at least a server for each 
       vo is known, else exit */
  
    if (confiles.empty()) {
      confiles.push_back(userconf);
      confiles.push_back(CONFILENAME);
    }
    else
      userconf="";

    if (!LoadVomses())
      exit(1);

    for (unsigned int i = 0; i < vomses.size(); i++) {
  
      Contact contact(vomses[i]);
    
      /* exit if any server for that vo known */
    
      std::vector<contactdata> servers;
      servers = v->FindByAlias(contact.vo().empty() ? contact.nick() : contact.vo());
      if (servers.empty()) {
        Print(ERROR) << "VOMS Server for " << vomses[i] << " not known!" << std::endl;
        exit(1);
      }
    
      if (listing)
        break;
    }
  }

  if (!certdir.empty())
    setenv("X509_CERT_DIR", certdir.c_str(), 1);

  /* prepare dataorder */
   
  dataorder = BN_new();
  if (!dataorder) 
    exit(1);
  BN_one(dataorder);
}

Client::~Client() {

  sk_X509_pop_free(cert_chain, X509_free);
  X509_free(ucert);
  EVP_PKEY_free(private_key);
  free(cacertfile);
  free(certdir);
  free(certfile);
  free(keyfile);
  free(outfile);

  if (v)
    delete v;

  BN_free(dataorder);

  OBJ_cleanup();

}

bool Client::Run() 
{
  /* set output file and environment */
  
  char * oldenv = getenv("X509_USER_PROXY");

  if (!noregen) {
    std::stringstream tmpproxyname;
    tmpproxyname << "/tmp/tmp_x509up_u" << getuid() << "_" << getpid();
    proxyfile = tmpproxyname.str();
    setenv("X509_USER_PROXY", proxyfile.c_str(), 1);
  }
  
  /* vomsdata */
  
  v->SetLifetime(ac_hours * 3600 + ac_minutes * 60);
  v->Order(ordering);
  v->AddTarget(targetlist);
  
  /* contacts servers for each vo */

  for(std::vector<std::string>::iterator i = vomses.begin(); i != vomses.end(); ++i) {
    if ((*i).empty())
      continue;

    /* will contain all fqans requested for the vo */
    std::vector<std::string> fqans;
    
    Contact contact(*i);

    /* find servers for that vo */
    std::vector<contactdata> servers;
    servers = v->FindByAlias(contact.nick());
    rand_wrapper rd(time(0));
    random_shuffle(servers.begin(), 
                   servers.end(),
                   rd);

    std::string vo = (contact.vo().empty() ? servers[0].vo : contact.vo());

    fqans.push_back(contact.fqan().empty() ? "/" + vo : contact.fqan());
    
    /* chech if other requests for the same vo exists */
    for (std::vector<std::string>::iterator j = i + 1; j < vomses.end(); ++j) {

      Contact tmp(*j);

      if ((tmp.vo() == vo) || (tmp.nick() == contact.nick())) {
        fqans.push_back(tmp.fqan().empty() ? "/" + vo : tmp.fqan());
        *j = "";
      }
    }

    /* parse fqans vector to build the command to send to the server */
    std::string command = parse_fqan(fqans);
    
    /* and contact them */

    std::string buffer;
    int version;

    (void)v->LoadCredentials(ucert, private_key, cert_chain);

    /* contact each server until one answers */
    for (std::vector<contactdata>::iterator beg = servers.begin(); beg != servers.end(); beg++) {
      /* create a temporary proxy to contact the server */  
      if (!noregen) {
        Print(INFO) << "Creating temporary proxy " << std::flush;
        Print(DEBUG) << "to " << proxyfile << " " << std::flush;

        int tmp = hours;
        hours = 1;
        if (CreateProxy("", NULL, (beg->version == -1 ? proxyver : beg->version/10)))
          goto err;
        hours = tmp;
      }
      
      /* contact server */
      Print(INFO) << "Contacting " << " " << beg->host << ":" << beg->port
                  << " [" << beg->contact << "] \"" << beg->vo << "\"" << std::flush;
      
      /* when called voms-proxy-list */
      if (listing)
        command = "N";

      int status = v->ContactRaw(beg->host, beg->port, beg->contact, command, buffer, version, timeout);

      /* print status */
      if (!status) {
        Print(INFO) << " Failed" << std::endl;
      }        
      else {
        Print(INFO) << " Done" << std::endl;
      }
      
      /* check for socket error */

      if (!status && v->error == VERR_NOSOCKET)
        Error();
      
      /* check for errors from the server */
      std::string serror = v->ServerErrors();
      if (!status && !serror.empty()) {
        Print(ERROR) << std::endl << "Error: " << serror << std::endl;
      }
      
      /* check for warnings from the server */
      if ((status && !serror.empty()) && !ignorewarn) {
        Print(WARN) << std::endl << "Warning: " << serror << std::endl << std::endl;
        
        if (failonwarn) {
          Print(WARN) << std::endl << "Error in getting data from VOMS server:" << beg->contact
                      << " (or in memorizing)" << std::endl;
          if (!noregen)
            unlink(proxyfile.c_str()); 
          exit(1);
        }
      }
      
      /* check for errors */
      std::string cerror = v->ErrorMessage();
      if (!status && serror.empty() && !cerror.empty()) {
        Print(ERROR) << std::endl << "Error: " << cerror << std::endl;
      }

      /* digest AC */
      if (status) {
        AC *ac;

        if ((ac = getAC(buffer))) {
          /* retrieve AC and add to list */
          if (!AddToList(ac)) {
            std::cerr << "Error while handling AC." << std::endl;
            if (!noregen)
              unlink(proxyfile.c_str()); 
            exit(3);
          }
          
          /* if contact succeded jumps to other vos */
          break;
        }
        else if (listing) {
          data += buffer;
          break;
        }
        else {
          Print(ERROR) << "\nError decoding AC." << std::endl
                       << "Error: " << v->ErrorMessage() << std::endl;
        }
      }

      if (beg != servers.end()-1) {
        Print(INFO) << std::endl << "Trying next server for " << beg->nick << "." << std::endl;
      }
      else {
        Print(ERROR) << std::endl << "None of the contacted servers for " << beg->vo << " were capable\nof returning a valid AC for the user." << std::endl;
        if (!noregen) 
          unlink(proxyfile.c_str());
        exit(1);
      }
    }
  }
  
  /* unlink tmp proxy file */

  if (!noregen)
    unlink(proxyfile.c_str()); 

  /* set output file and environment */
  
  proxyfile = outfile;
  setenv("X509_USER_PROXY", proxyfile.c_str(), 1);  
  
  /* with separate write info to file and exit */
  
  if (!separate.empty() && (!data.empty() || aclist)) {
    if (!WriteSeparate()) {
      Print(ERROR) << "Wasn't able to write to " << separate << std::endl;
      exit(1);
    }
    exit(0);
  }

  if (listing) {
    Print(FORCED) << "Available attributes:\n" << data <<std::endl;
    exit(0);
  }

  if (!data.empty())
    Print(FORCED) << "RECEIVED DATA:\n" << data << std::endl;

  if (!acfile.empty()) {
    AC *ac = ReadSeparate(acfile);
    if (ac)
      (void)AddToList(ac);
    else {
      Print(ERROR) << "Error while reading AC from file: " << acfile << std::endl << std::flush;
      exit(1);
    }
  }
  
  /* create a proxy containing the data retrieved from VOMS servers */
  
  Print(INFO)  << "Creating proxy " << std::flush; 
  Print(DEBUG) << "to " << proxyfile << " " << std::flush;

  if (CreateProxy(data, aclist ? aclist : NULL, proxyver)) {
    goto err;
  }
  else 
    free(aclist);
  
  Print(INFO) << "\n" << std::flush;

  /* unset environment */
  
  if (!oldenv)
    unsetenv("X509_USER_PROXY");
  else {
    setenv("X509_USER_PROXY", oldenv, 1);
  }
  
  /* assure user certificate is not expired or going to, else advise but still create proxy */
  
  if (Test())
    return false;
  
  return Verify(true);

 err:
  
  Error();
  Print(ERROR) << "ERROR: " << v->ErrorMessage() << std::endl;
  return false;

}

bool Client::CreateProxy(std::string data, AC ** aclist, int version) 
{
  struct VOMSProxyArguments *args = VOMS_MakeProxyArguments();
  int ret = -1;

  if (args) {
    args->proxyfilename = strdup(proxyfile.c_str());
    if (!incfile.empty())
      args->filename      = strdup(incfile.c_str());
    args->aclist        = aclist;
    args->proxyversion  = version;
    if (!data.empty()) {
      args->data          = (char*)data.data();
      args->datalen       = data.length();
    }
    args->newsubject       = NULL;
    args->newsubjectlen    = 0;
    args->cert          = ucert;
    args->chain         = cert_chain;
    args->key           = private_key;
    args->bits          = bits;
    if (!policyfile.empty())
      args->policyfile    = strdup(policyfile.c_str());
    if (!policylang.empty())
      args->policylang    = strdup(policylang.c_str());
    args->pathlength    = pathlength;
    args->hours         = hours;
    args->minutes       = minutes;
    args->limited       = limit_proxy;

    args->voID          = strdup(voID.c_str());
    args->callback      = (int (*)())kpcallback;
    int warn = 0;
    void *additional = NULL;

    struct VOMSProxy *proxy = VOMS_MakeProxy(args, &warn, &additional);

    ProxyCreationError(warn, additional);

    if (proxy)
      ret = VOMS_WriteProxy(proxyfile.c_str(), proxy);

    Print(INFO) << " Done" << std::endl << std::flush;

    VOMS_FreeProxy(proxy);
    VOMS_FreeProxyArguments(args);


  }

  return ret == -1;
}

void Client::ProxyCreationError(int error, void *additional)
{
  switch (error) {
  case PROXY_NO_ERROR:
    break;

  case PROXY_ERROR_OPEN_FILE:
    Print(ERROR) << "Error: cannot open file: " 
                 << (char *)additional << std::endl;
    Print(ERROR) << strerror(errno) << std::endl;
    break;

  case PROXY_ERROR_FILE_READ:
    Print(ERROR) << "Error: cannot read from file: "
                 << (char *)additional << std::endl;
    Print(ERROR) << strerror(errno) << std::endl;
    break;

  case PROXY_ERROR_STAT_FILE:
    Print(ERROR) << "Error: cannot stat file: " 
                 << (char *)additional << std::endl;
    Print(ERROR) << strerror(errno) << std::endl;
    break;

  case PROXY_ERROR_OUT_OF_MEMORY:
    Print(ERROR) << "Error: out of memory" << std::endl;
    break;

  case PROXY_WARNING_GSI_ASSUMED:
    Print(DEBUG) << "\nNo policy language specified, Gsi impersonation proxy assumed." << std::endl;
    break;

  case PROXY_WARNING_GENERIC_LANGUAGE_ASSUMED:
    Print (DEBUG) << "\nNo policy language specified with policy file, assuming generic." << std::endl;
    break;

  default:
    Print(ERROR) << "Unknown error" << std::endl;
    break;
  }
}

AC *Client::ReadSeparate(const std::string& file) 
{
  BIO *in = BIO_new(BIO_s_file());

  int res = BIO_read_filename(in, (char*)(file.c_str()));
  AC * ac = NULL;

  if (res)
#ifdef TYPEDEF_I2D_OF
    ac = (AC*)PEM_ASN1_read_bio((d2i_of_void*)d2i_AC, "ATTRIBUTE CERTIFICATE", in, NULL, NULL, NULL);
#else
  ac = (AC*)PEM_ASN1_read_bio(((char * (*)())d2i_AC), "ATTRIBUTE CERTIFICATE", in, NULL, NULL, NULL);
#endif
  BIO_free(in);

  return ac;
}

bool Client::WriteSeparate() 
{
  if (aclist) {
    
    BIO * out = BIO_new(BIO_s_file());

    if (data.empty())
      BIO_write_filename(out, (char *)separate.c_str());
    else BIO_write_filename(out, (char *)(separate+".ac").c_str());
    
    while(*aclist) {
#ifdef TYPEDEF_I2D_OF
      if (!PEM_ASN1_write_bio((i2d_of_void *)i2d_AC, "ATTRIBUTE CERTIFICATE", out, (char *)*(aclist++), NULL, NULL, 0, NULL, NULL))
#else
      if (!PEM_ASN1_write_bio(((int (*)())i2d_AC), "ATTRIBUTE CERTIFICATE", out, (char *)*(aclist++), NULL, NULL, 0, NULL, NULL))
#endif
        {
          Print(INFO) << "Unable to write to BIO" << std::endl;
          return false;;
        }
    }

    BIO_free(out);
  
    if (data.empty())
      Print(INFO) << "Wrote ACs to " << separate << std::endl;
  }
  
  if (!data.empty()) {
    if (aclist) {
      Print(INFO) << "Wrote ACs to " << separate+".ac" << std::endl;      
    }
    
    std::ofstream fs;
    fs.open((separate+".data").c_str());

    if (!fs) {
      Print(ERROR) << "cannot open file: " << separate+".data" << std::endl;
      return false;
    }
    else {
      for (std::string::iterator pos = data.begin(); pos != data.end(); pos++)
        fs << *pos;
      fs.close();
    }
    
    Print(INFO) << "Wrote data to " << separate+".data" << std::endl;

  }

  return true;
}

bool Client::Verify(bool doproxy) 
{

  X509 *cert = ucert;
  STACK_OF(X509) *chain = cert_chain;

  if (doproxy) {
    load_credentials(outfile, outfile, &cert, &chain, NULL, pw_cb);
  }

  /* First step:  Verify certificate chain. */
  proxy_verify_ctx_init(&pvxd);
  proxy_verify_init(&pvd, &pvxd);
  pvxd.certdir = this->certdir;

  if (proxy_verify_cert_chain(cert, chain, &pvd)) {
    if (doproxy) {
      /* Second step: Verify AC. */
      if (!v->Retrieve(cert, chain, RECURSE_CHAIN)) {
        if (v->error != VERR_NOEXT) {
          Print(ERROR) << "Error: verify failed." << std::endl
                       << v->ErrorMessage() << std::endl;
          return false;
        }
      }
    }
    if (verify) 
      Print(FORCED) << "verify OK" << std::endl; 
    return true;
  }
  else {
    Print(ERROR) << "Error: Certificate verify failed." << std::endl;
    Error();
    return false;
  }

  // Should never reach here

  Error();
  return false;
}

bool Client::Test() 
{
  ASN1_UTCTIME * asn1_time = ASN1_UTCTIME_new();
  X509_gmtime_adj(asn1_time, 0);
  time_t time_now = ASN1_UTCTIME_mktime(asn1_time);
  ASN1_UTCTIME_free(asn1_time);
  time_t time_after = ASN1_UTCTIME_mktime(X509_get_notAfter(ucert));
  time_t time_diff = time_after - time_now ;
  int length  = hours*60*60 + minutes*60;

  if (time_diff < 0) {
    Print(WARN) << std::endl << "ERROR: Your certificate expired "
                << asctime(localtime(&time_after)) << std::endl;
    
    return 2;
  } 
  
  if (hours && time_diff < length) {
    Print(WARN) << std::endl << "Warning: your certificate and proxy will expire "
                << asctime(localtime(&time_after))
                << "which is within the requested lifetime of the proxy"
                << std::endl;
    return 1;
  }
  
  if (!quiet) {
    time_t time_after_proxy;
    time_after_proxy = time_now + length;
    
    Print(INFO) << "Your proxy is valid until "
                << asctime(localtime(&time_after_proxy)) << std::flush;
  }

  return 0;
}

bool Client::AddToList(AC *ac) 
{
  AC **actmplist = NULL;

  if (!ac)
    return false;

  actmplist = (AC **)listadd((char **)aclist, (char *)ac, sizeof(AC *));


  if (actmplist) {
    /* Only for comaptibility with APIs version <= 1.5 */

    aclist = actmplist;
    (void)BN_lshift1(dataorder, dataorder);
    (void)BN_set_bit(dataorder, 0);
    return true;
  }
  else {
    listfree((char **)aclist, (freefn)AC_free);
    Error();
    return false;
  }

  /* Control should never reach here */
  /*   return false; */
}

bool Client::checkstats(char *file, int mode)
{
  struct stat stats;

  if (stat(file, &stats) == -1) {
    Print(ERROR) << "Unable to find user certificate or key: " << file << std::endl;
    return false;
  }

  if (stats.st_mode & mode) {
    Print(ERROR) << std::endl << "ERROR: Couldn't find valid credentials to generate a proxy." << std::endl 
                 << "Use --debug for further information." << std::endl;
    Print(DEBUG) << "Wrong permissions on file: " << file << std::endl;

    return false;
  }
  return true;
}


bool Client::pcdInit() {

  int status = false;

  ERR_load_prxyerr_strings(0);
  SSLeay_add_ssl_algorithms();

  
  if (!determine_filenames(&cacertfile, &certdir, &outfile, &certfile, &keyfile, noregen ? 1 : 0))
    goto err;

  if (certfile == keyfile) 
    keyfile = strdup(certfile);

  if (!noregen) {
    if (certfile)
      setenv("X509_USER_CERT", certfile, 1);

    if (keyfile)
      setenv("X509_USER_KEY", keyfile, 1);
  }
  else {
    if (outfile) {
      setenv("X509_USER_CERT", outfile, 1);
      setenv("X509_USER_KEY", outfile, 1);
    }
  }
  
  // verify that user's certificate and key have the correct permissions

  if (!checkstats(certfile, S_IXUSR | S_IWGRP | S_IXGRP | S_IWOTH | S_IXOTH) ||
      !checkstats(keyfile, S_IXUSR | S_IRGRP | S_IWGRP | S_IXGRP | S_IRGRP |
                  S_IWOTH | S_IXOTH))
    exit(1);
  
  Print(DEBUG) << "Files being used:" << std::endl 
               << " CA certificate file: " << (cacertfile ? cacertfile : "none") << std::endl
               << " Trusted certificates directory : " << (certdir ? certdir : "none") << std::endl
               << " Proxy certificate file : " << (outfile ? outfile : "none") << std::endl
               << " User certificate file: " << (certfile ? certfile : "none") << std::endl
               << " User key file: " << (keyfile ? keyfile : "none") << std::endl
               << "Output to " << outfile << std::endl;

  if (!load_credentials(certfile, keyfile, &ucert, &cert_chain, &private_key, pw_cb))
    goto err;

  if (!quiet) {
    char * s = NULL;
    s = X509_NAME_oneline(X509_get_subject_name(ucert),NULL,0);
    Print(INFO) << "Your identity: " << s << std::endl;
    OPENSSL_free(s);
  }

  status = true;
  
 err:
  Error();
  return status;
  
}

void Client::Error() 
{
  unsigned long l;
  char buf[256];
#if SSLEAY_VERSION_NUMBER  >= 0x00904100L
  const char *file;
#else
  char *file;
#endif
  char *dat;
  int line;
    
  /* WIN32 does not have the ERR_get_error_line_data */ 
  /* exported, so simulate it till it is fixed */
  /* in SSLeay-0.9.0 */
  
  while ( ERR_peek_error() != 0 ) {
    
    int i;
    ERR_STATE *es;
      
    es = ERR_get_state();
    i = (es->bottom+1)%ERR_NUM_ERRORS;
    
    if (es->err_data[i] == NULL)
      dat = strdup("");
    else
      dat = strdup(es->err_data[i]);

    if (dat) {
      l = ERR_get_error_line(&file, &line);

      if (debug)
        std::cerr << ERR_error_string(l,buf) << ":"
                  << file << ":" << line << dat << std::endl;
      else
        std::cerr << ERR_reason_error_string(l) << dat
                  << "\nFunction: " << ERR_func_error_string(l) << std::endl;
    }
    
    free(dat);
  }
}

static AC *getAC(const std::string& data)
{
  char *p, *pp;
  AC *ac = NULL;
  int len = data.size();

  pp = (char *)malloc(len);

  if (pp) {
    pp = (char *)memcpy(pp, data.data(), len);
    p = pp;
    ac = d2i_AC(NULL, (unsigned char **)&p, len);
    free(pp);
  }

  return ac;
}

bool Client::LoadVomses()
{
  bool failfatal   = failonwarn  || confiles.size() == 1;
  bool alwaysprint = !ignorewarn || confiles.size() == 1;

  for (std::vector<std::string>::iterator i = confiles.begin(); i != confiles.end(); i++) {
    if (debug)
      std::cout << "Using configuration file "<< *i << std::endl;

    bool res = v->LoadSystemContacts(*i);

    if (!res) {
      if (v->error == VERR_FORMAT) {
        Print(ERROR) << v->ErrorMessage() << std::endl;
        return false;
      }
      else if (v->error == VERR_DIR) {
        /* Ignore errors while reading default file
           unless that is the only file */
        if (*i != userconf || confiles.size() == 1) {
          if (alwaysprint)
            Print(ERROR) << v->ErrorMessage() << std::endl;
          if (failfatal)
            return false;
        }
      }
    }
  }
  return true;
}

struct nullstream: std::ostream {
  struct nullbuf: std::streambuf {
    int overflow(int c) { return traits_type::not_eof(c); }
  } m_sbuf;
  nullstream(): std::ios(&m_sbuf), std::ostream(&m_sbuf) {}
};

nullstream voidstream;

std::ostream& Client::Print(message_type type) 
{
  if (type == FORCED)
    return std::cout;

  if (type == ERROR || (failonwarn && type == WARN))
    return std::cerr;

  if (quiet || (ignorewarn && type == WARN))
    return voidstream;

  if (type == WARN)
    return std::cerr;

  if (type == DEBUG && !debug)
    return voidstream;

  return std::cout;
}
