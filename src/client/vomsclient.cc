/*********************************************************************
 *
 * Authors: Vincenzo Ciaschini - Vincenzo.Ciaschini@cnaf.infn.it 
 *          Valerio Venturi - Valerio.Venturi@cnaf.infn.it 
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

extern "C" 
{
#include "proxycertinfo.h"
}

#include "init.h"

static bool isAC(std::string data);

const std::string SUBPACKAGE      = "voms-proxy-init";

/* use name specific to each distribution (defined in configure.in) */

const std::string location = (getenv(LOCATION_ENV) ? getenv(LOCATION_ENV) : LOCATION_DIR);
const std::string CONFILENAME     = (location + "/etc/vomses");
const std::string USERCONFILENAME = std::string(USER_DIR) + std::string("/vomses");

/* global variable for output control */

bool debug = false;
bool quiet = false;

extern "C" {
  
static int (*pw_cb)() = NULL;

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
  
static void kpcallback(int p, int n) {
    
  char c='B';
    
  if (quiet) return;
    
  if (p == 0) c='.';
  if (p == 1) c='+';
  if (p == 2) c='*';
  if (p == 3) c='\n';
  if (!debug) c = '.';
  fputc(c,stderr);
  
}
  
extern int proxy_verify_cert_chain(X509 * ucert, STACK_OF(X509) * cert_chain, proxy_verify_desc * pvd);
extern void proxy_verify_ctx_init(proxy_verify_ctx_desc * pvxd);
  
}

Client::Client(int argc, char ** argv) :
                                           ignorewarn(false),
                                           failonwarn(false),
                                           confile(CONFILENAME),
                                           userconf(""),
                                           incfile(""),
                                           separate(""),
                                           bits(512),
                                           hours(12),
                                           minutes(0),
                                           ac_hours(12),
                                           ac_minutes(0),
                                           limit_proxy(false),
                                           proxyver(0),
                                           pathlength(1),
                                           verify(false),
                                           noregen(false),
                                           version(0),
#ifdef CLASS_ADD
                                           classs_add_buf(NULL),
                                           class_add_buf_len(0),
#endif 
                                           dataorder(NULL),
                                           pcd(NULL),
                                           aclist(NULL),
                                           voID(""),
                                           listing(false)
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
  std::vector<std::string> confiles;

  bool pwstdin = false;

  if (strrchr(argv[0],'/'))
    program = strrchr(argv[0],'/') + 1;
  else
    program = argv[0];

  if ((strcmp(program.c_str(), "voms-proxy-list") == 0) || (strcmp(program.c_str(), "edg-voms-proxy-list") == 0))
    listing = true;
  
  /* usage message */

  static char *LONG_USAGE = NULL;

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
      "    -valid <h:m>                   Proxy is valid for h hours and m minutes (default to 12:00)\n" \
      "    -hours H                       Proxy is valid for H hours (default:12)\n" \
      "    -bits                          Number of bits in key {512|1024|2048|4096}\n" \
      "    -cert     <certfile>           Non-standard location of user certificate\n" \
      "    -key      <keyfile>            Non-standard location of user key\n" \
      "    -certdir  <certdir>            Non-standard location of trusted cert dir\n" \
      "    -out      <proxyfile>          Non-standard location of new proxy cert\n" \
      "    -voms <voms<:command>>         Specify voms server. :command is optional.\n" \
      "    -order <group<:role>>          Specify ordering of attributes.\n" \
      "    -target <hostname>             Targets the AC against a specific hostname.\n" \
      "    -vomslife <h:m>                Try to get a VOMS pseudocert valid for h hours and m minutes (default to value of -valid).\n" \
      "    -include <file>                Include the contents of the specified file.\n" \
      "    -conf <file>                   Read options from <file>.\n" \
      "    -confile <file>                Non-standard location of voms server addresses.\n" \
      "    -userconf <file>               Non-standard location of user-defined voms server addresses.\n" \
      "    -vomses <file>                 Non-standard loation of configuration files.\n"
      "    -policy <policyfile>           File containing policy to store in the ProxyCertInfo extension.\n" \
      "    -pl, -policy-language <oid>    OID string for the policy language.\n" \
      "    -policy-language <oid>         OID string for the policy language.\n" \
      "    -path-length <l>               Allow a chain of at most l proxies to be generated from this ones.\n" \
      "    -globus                        Globus version.\n" \
      "    -proxyver                      Version of proxy certificate.\n" \
      "    -noregen                       Use existing proxy certificate to connect to server and sign the new proxy.\n" \
      "    -separate <file>               Saves the informations returned by the server on file <file>.\n" \
      "    -ignorewarn                    Ignore warnings.\n" \
      "    -failonwarn                    Treat warnings as errors.\n" \
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
#ifdef CLASS_ADD
      {"classadd",        1, (int *)class_add_buf,OPT_STRING},
#endif
      {0, 0, 0, 0}
    };

    if (!getopts(argc, argv, opts))
      exit(1);
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
      "    -voms <voms<:command>>         Specify voms server. :command is optional.\n" \
      "    -include <file>                Include the contents of the specified file.\n" \
      "    -conf <file>                   Read options from <file>.\n" \
      "    -confile <file>                Non-standard location of voms server addresses.\n" \
      "    -userconf <file>               Non-standard location of user-defined voms server addresses.\n" \
      "    -vomses <file>                 Non-standard loation of configuration files.\n"
      "    -globus                        Globus version.\n" \
      "    -noregen                       Use existing proxy certificate to connect to server and sign the new proxy.\n" \
      "    -ignorewarn                    Ignore warnings.\n" \
      "    -failonwarn                    Treat warnings as errors.\n" \
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
      {0, 0, 0, 0}
    };

    if (!getopts(argc, argv, opts))
      exit(1);

    if (vomses.size() != 1) {
      std::cerr << "Exactly ONE voms server must be specified!\n" << std::endl;
      if(vomses.size() == 0)
        exit(0);
      std::cerr << "Ignoring all subsequent servers.\n" << std::endl;
    }
  }
  
  /* wouldn't make sense */

  if (failonwarn)
    ignorewarn = false;
  
  if(debug)
    quiet = false;

  /* show version and exit */
  
  if (progversion) {
    std::cout << SUBPACKAGE << "\nVersion: " << VERSION << std::endl;
    std::cout << "Compiled: " << __DATE__ << " " << __TIME__ << std::endl;
    exit(0);
  }

  /* set globus version */

  version = globus(version);
  if (version == 0) {
    version = 22;
    if(debug) std::cout << "Unable to discover Globus version: trying for 2.2" << std::endl;
  }
  else 
    if(debug) std::cout << "Detected Globus version: " << version << std::endl;
  
  /* set proxy version */
  
  if(proxyver!=2 && proxyver!=3 && proxyver!=0) {
    std::cerr << "Error: proxyver must be 2 or 3" << std::endl;
    exit(1);
  }
  else if(proxyver==0) {
    if(debug)
      std::cout << "Unspecified proxy version, settling on Globus version: ";
    if(version<30)
      proxyver = 2;
    else proxyver = 3;
    if(debug)
      std::cout << proxyver << std::endl;
  }
  
  /* PCI extension option */ 
  
  if(proxyver==3)
  {
    if(!policylang.empty())
      if(policyfile.empty()) {
	std::cerr << "Error: if you specify a policy language you also need to specify a policy file" << std::endl;
	exit(1);
      }
  }
  
  if(proxyver==3)
  {
    if(debug) std::cout << "PCI extension info: " << std::endl << " Path length: " << pathlength << std::endl;
    if(policylang.empty())
      if(debug) std::cout << " Policy language not specified." << policylang << std::endl;
      else if(debug) std::cout << " Policy language: " << policylang << std::endl;
    if(policyfile.empty())
      if(debug) std::cout << " Policy file not specified." << std::endl;
      else if(debug) std::cout << " Policy file: " << policyfile << std::endl;
  }
  
  /* get vo */
  
  char *vo = getenv("VO");
  if (vo != NULL && strcmp(vo, "") != 0)
    voID = vo;
  
  /* controls that number of bits for the key is appropiate */
  
  if((bits!=512) && (bits!=1024) && (bits!=2048) && (bits!=4096)) {
    std::cerr << "Error: number of bits in key must be one of 512, 1024, 2048, 4096." << std::endl;
    exit(1);
  }
  else if(debug) std::cout << "Number of bits in key :" << bits << std::endl; 
  
  /* parse valid options */

  if (!valid.empty())
  {
    std::string::size_type pos = valid.find(':');
    if (pos != std::string::npos && pos > 0) 
    {
      hours  = ac_hours = atoi(valid.substr(0, pos).c_str());
      minutes = ac_minutes = atoi(valid.substr(pos+1).c_str());
    }
    else 
    {
      std::cerr << "-valid argument must be in the format: h:m" << std::endl;
      exit(1);
    }
    if(hours < 0)
    {
      std::cerr << "-valid argument must be in the format: h:m" << std::endl;
      exit(1);
    }    
    if(minutes < 0 || minutes >59)
    {
      std::cerr << "specified minutes must be in the range 0-59" << std::endl;
      exit(1);
    }
  }

  /* parse vomslife options */

  if (!vomslife.empty())
  {
    std::string::size_type pos = vomslife.find(':');
    if (pos != std::string::npos && pos > 0) 
    {
      ac_hours   = atoi(vomslife.substr(0, pos).c_str());
      ac_minutes = atoi(vomslife.substr(pos+1).c_str());
    }
    else 
    {
      std::cerr << "-vomslife argument must be in the format: h:m" << std::endl;
      exit(1);
    }
    if(ac_hours < 0)
    {
      std::cerr << "-valid argument must be in the format: h:m" << std::endl;
      exit(1);
    }    
    if(ac_minutes < 0 || ac_minutes >59)
    {
      std::cerr << "specified minutes must be in the range 0-59" << std::endl;
      exit(1);
    }
  }

  /* allow password from stdin */
  
  if(pwstdin)
    pw_cb = (int (*)())(pwstdin_callback);

  /* configuration files */

  if (userconf.empty()) {
    char *uc = getenv("VOMS_USERCONF");
    if (uc)
      userconf = uc;
  }
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
  
  /* preliminary controls a server for each vo is known, else exit */
  
  vomsdata v;

  confiles.push_back(userconf);
  confiles.push_back(CONFILENAME);

  for (std::vector<std::string>::iterator i = confiles.begin(); i != confiles.end(); i++) {
    if(debug)
      std::cout << "Using configuration file "<< *i << std::endl;
    if (!v.LoadSystemContacts(*i))
      std::cerr << v.ErrorMessage() << std::endl;
  }

  //  v.LoadSystemContacts(confile);
  //  v.LoadUserContacts(userconf);
  
  for (unsigned int i = 0; i < vomses.size(); i++) {
  
    std::string tmp = vomses[i];
    
    /* separate nick from fqan */
    
    std::string nick;
    std::string::size_type pos = tmp.find(':');
    
    if (pos != std::string::npos && pos > 0)
      nick = tmp.substr(0, pos);
    else 
      nick = tmp;
    
    /* exit if any server for that vo known */

    std::vector<contactdata> servers;
    servers = v.FindByAlias(nick);
    if (servers.empty()) {
      std::cerr << "VOMS Server for " << nick << " not known!" << std::endl;
      exit(1);
    }
    
    if(listing)
      break;
  }

  /* file used */
  
  this->cacertfile = NULL;
  this->certdir = (certdir.empty() ? NULL : const_cast<char *>(certdir.c_str()));
  this->outfile = (outfile.empty() ? NULL : const_cast<char *>(outfile.c_str()));
  this->certfile = (certfile.empty() ? NULL : const_cast<char *>(certfile.c_str()));
  this->keyfile = (keyfile.empty() ? NULL : const_cast<char *>(keyfile.c_str()));

  /* prepare dataorder */
   
  dataorder = BN_new();
  if (!dataorder) 
    exit(1);
  BN_one(dataorder);

  /* prepare proxy_cred_desc */

  if(!pcdInit())
    exit(3);

  /* verify if the cert is good i.e. is signed by one of the trusted CAs. */

  if(verify)
    if(!Verify())
      exit(3);
}

Client::~Client() {

  if(cacertfile)  
    free(cacertfile);
  if(certdir)  
    free(certdir);
  if(certfile)  
    free(certfile);
  if(keyfile)  
    free(keyfile);
  if(outfile)  
    free(outfile);

  if(pcd)
    proxy_cred_desc_free(pcd);
  if (dataorder)
    BN_free(dataorder);

  OBJ_cleanup();

}

bool Client::Run() {

  bool ret = true;
  std::string filedata;

  /* check if the certificate expected to sign the proxy is expired */
  if(!vomses.empty())
  {
    time_t not_after = ASN1_UTCTIME_mktime(X509_get_notAfter(pcd->ucert));
    if ((time(0) - not_after)>0)
    {
      std::cerr << std::endl << "ERROR: Your certificate expired "
                << asctime(localtime(&not_after)) << std::endl;
      exit(1);
    }
  }

  /* set output file and environment */
  
  char * oldenv = getenv("X509_USER_PROXY");

  if(!noregen) {
    std::stringstream tmpproxyname;
    tmpproxyname << "/tmp/tmp_x509up_u" << getuid() << "_" << getpid();
    proxyfile = tmpproxyname.str();
    setenv("X509_USER_PROXY", proxyfile.c_str(), 1);
  }
  
  /* vomsdata */
  
  vomsdata v;
  v.LoadSystemContacts(confile);
  v.LoadUserContacts(userconf);
  v.SetLifetime(ac_hours * 3600 + ac_minutes * 60);
  v.Order(ordering);
  v.AddTarget(targetlist);
  
  /* contacts servers for each vo */

  for (unsigned int i = 0; i < vomses.size(); i++) {
    
    std::string tmp = vomses[i];

    /* separate nick from fqan */
    
    std::string fqan;
    std::string nick;
    std::string::size_type pos = tmp.find(':');
    if (pos != std::string::npos && pos > 0) {
      fqan = tmp.substr(pos+1);
      nick = tmp.substr(0, pos);
    }
    else nick = tmp;
    
    /* find servers for that vo */
    
    std::vector<contactdata> servers;
    servers = v.FindByAlias(nick);
    if (!servers.empty())
      random_shuffle(servers.begin(), servers.end());
    
    /* and contact them */

    std::string buffer;
    int version;
    
    for (std::vector<contactdata>::iterator beg = servers.begin(); beg != servers.end(); beg++) {
  
      if(!noregen) {
	
        /* create a temporary proxy to contact the server */  
	
        if(!quiet) std::cout << "Creating temporary proxy " << std::flush;
        if(debug) std::cout << "to " << proxyfile << " " << std::flush;
        int tmp = hours;
        hours = 1;
        if(CreateProxy("", "", NULL, (beg->version == -1 ? proxyver : beg->version)))
          goto err;
        hours = tmp;
      }
      
      /* parse fqan */
      
      std::string command;
      if(!fqan.empty())
        command = FQANParse(fqan);
      else command = "G/" + beg->vo; 
      
      /* contact server */
      
      if(!quiet) std::cout << "Contacting " << " " << beg->host << ":" << beg->port
                           << " [" << beg->contact << "] \"" << beg->vo << "\"" << std::flush;
      
      if (listing)
        command = "N";

      int status = v.ContactRaw(beg->host, beg->port, beg->contact, command, buffer, version);
      
      /* check for errors from the server */
      
      std::string error = v.ServerErrors();

      if (!status && v.error == VERR_NOSOCKET)
        Error();
      
      if (!status && !error.empty()) {
        std::cerr << std::endl << "Error: " << error << std::endl;
        exit(1);
      }

      /* check for warnings from the server */

      if(!ignorewarn && !error.empty()) {

        if(!quiet) 
          std::cerr << std::endl << "Warning: " << error << std::endl << std::endl;
        
        if(failonwarn) {
          if (!quiet)
            std::cerr << std::endl << "Error in getting data from VOMS server:" << beg->contact
                      << " (or in memorizing)" << std::endl;
          exit(1);
        }
      }
      
      /* check for errors */
      
      error = v.ErrorMessage();

      if (!status && !error.empty()) {
        std::cerr << std::endl << "Error: " << error << std::endl;
        exit(1);
      }

      if (isAC(buffer)) {
        
        if (status) {
          
          std::cout << " Done" << std::endl;
          
          /* retrieve AC and add to list */
        
          if (!Retrieve(buffer)) {
            std::cerr << "\nError decoding AC." << std::endl;
            std::cerr << "Error: " << v.ErrorMessage() << std::endl;
            exit(3);
          }


        
          // if contact succeded jumps to other vos */
          break;
        }
        else if(!quiet) 
          std::cout << " Failed";
      }
      else {
        data += buffer;
        break;
      }

      /* check for errors */
      
//       static std::string retmsg[] = { "VERR_NONE", "VERR_NOSOCKET", "VERR_NOIDENT", "VERR_COMM", 
// 				      "VERR_PARAM", "VERR_NOEXT", "VERR_NOINIT",
// 				      "VERR_TIME", "VERR_IDCHECK", "VERR_EXTRAINFO",
// 				      "VERR_FORMAT", "VERR_NODATA", "VERR_PARSE",
// 				      "VERR_DIR", "VERR_SIGN", "VERR_SERVER", 
// 				      "VERR_MEM", "VERR_VERIFY", "VERR_TYPE",
// 				      "VERR_ORDER", "VERR_SERVERCODE"};      
      
      if(!quiet) {
        std::cerr << "\n Error: " << v.ErrorMessage() << std::endl;
      }

      if(beg != servers.end()-1) 
      {
        if(!quiet) std::cout << std::endl << "Trying next server for " << beg->nick << "." << std::endl;
      }
      else 
      {
        if (!quiet) std::cout << std::endl << "Failed to contact servers for " << beg->vo << "." << std::endl;
        if(!noregen) 
          unlink(proxyfile.c_str());
        exit(1);
      }
    }
  }
  
  /* unlink tmp proxy file */

  if(!noregen)
    unlink(proxyfile.c_str()); 

  /* set output file and environment */
  
  proxyfile = outfile;
  setenv("X509_USER_PROXY", proxyfile.c_str(), 1);  
  
  /* include file */
  
  if (!incfile.empty())
    if(!IncludeFile(filedata))
      if(!quiet) std::cout << "Wasn't able to include file " << incfile << std::endl;;
  
  /* with separate write info to file and exit */
  
  if (!separate.empty() && (!data.empty() || aclist)) {
    if(!WriteSeparate())
      if(!quiet) std::cout << "Wasn't able to write to " << separate << std::endl;
    exit(0);
  }

  if (listing) {
    std::cout << "Available attributes:\n" << data <<std::endl;
    exit(0);
  }

  if (!data.empty())
    std::cout << "RECEIVED DATA:\n" << data << std::endl;
  
  /* create a proxy containing the data retrieved from VOMS servers */
  
  if(!quiet) std::cout << "Creating proxy " << std::flush; 
  if(debug) std::cout << "to " << proxyfile << " " << std::flush;
  if(CreateProxy(data, filedata, vomses.empty() ? NULL : aclist, proxyver)) {
    listfree((char **)aclist, (freefn)AC_free);
    goto err;
  }
  else
    free(aclist);
  
  /* unset environment */
  
  if (!oldenv)
    unsetenv("X509_USER_PROXY");
  else {
    setenv("X509_USER_PROXY", oldenv, 1);
  }
  free(oldenv);
  
  /* assure user certificate is not expired or going to, else advise but still create proxy */
  
  if(!Test())
    ret = false;
  
  return ret;

 err:
  
  Error();
  std::cerr << "ERROR: " << v.ErrorMessage() << std::endl;
  return false;

}

bool Client::CreateProxy(std::string data, std::string filedata, AC ** aclist, int version) {

  bool status = true;
  char *confstr = NULL;

  X509 * ncert = NULL;
  EVP_PKEY * npkey;
  X509_REQ * req;
  BIO * bp = NULL;
  STACK_OF(X509_EXTENSION) * extensions = NULL;
  X509_EXTENSION *ex1 = NULL, *ex2 = NULL, *ex3 = NULL, *ex4 = NULL, *ex5 = NULL, *ex6 = NULL, *ex7 = NULL, *ex8 = NULL;
  bool voms, classadd, file, vo, acs, info, kusg, order;
  order = acs = vo = voms = classadd = file = kusg = false;
  
  FILE *fpout = fopen(proxyfile.c_str(), "w");
  if (fpout == NULL) {
    PRXYerr(PRXYERR_F_LOCAL_CREATE, PRXYERR_R_PROBLEM_PROXY_FILE);
    ERR_add_error_data(2, "\nOpen failed for File=", proxyfile.c_str());
    goto err;
  }
  
#ifndef WIN32
  if (fchmod(fileno(fpout),0600) == -1) {
    PRXYerr(PRXYERR_F_LOCAL_CREATE, PRXYERR_R_PROBLEM_PROXY_FILE);
    ERR_add_error_data(2, "\n        chmod failed for File=", proxyfile.c_str());
    goto err;
  }
#endif
  
  if (proxy_genreq(pcd->ucert, &req, &npkey, bits, (int (*)())kpcallback, pcd))
    goto err;

  /* Add proxy extensions */

  /* initialize extensions stack */

  if ((extensions = sk_X509_EXTENSION_new_null()) == NULL) {
    PRXYerr(PRXYERR_F_PROXY_SIGN, PRXYERR_R_CLASS_ADD_EXT);
    goto err;
  }
  
  /* voms extension */
  
  if (data.size()) {
    
    if ((ex1 = CreateProxyExtension("voms", data)) == NULL) {
      PRXYerr(PRXYERR_F_PROXY_SIGN, PRXYERR_R_CLASS_ADD_EXT);
      goto err;
    }
    
    if (!sk_X509_EXTENSION_push(extensions, ex1)) {
      PRXYerr(PRXYERR_F_PROXY_SIGN, PRXYERR_R_CLASS_ADD_EXT);
      goto err;
    }
    
    voms = true;
  }

  /* include extension */

  if (!filedata.empty()) {
    
    if ((ex3 = CreateProxyExtension("incfile", filedata)) == NULL) {
      PRXYerr(PRXYERR_F_PROXY_SIGN, PRXYERR_R_CLASS_ADD_EXT);
      goto err;
    }

    if (!sk_X509_EXTENSION_push(extensions, ex3)) {
      PRXYerr(PRXYERR_F_PROXY_SIGN, PRXYERR_R_CLASS_ADD_EXT);
      goto err;
    }

    file = true;
  }

  /* AC extension  */

  if (aclist) {

    if ((ex5 = X509V3_EXT_conf_nid(NULL, NULL, OBJ_txt2nid("acseq"), (char *)aclist)) == NULL) {
      PRXYerr(PRXYERR_F_PROXY_SIGN, PRXYERR_R_CLASS_ADD_EXT);
      goto err;
    }
    
    if (!sk_X509_EXTENSION_push(extensions, ex5)) {
      PRXYerr(PRXYERR_F_PROXY_SIGN, PRXYERR_R_CLASS_ADD_EXT);
      goto err;
    }
    
    acs = true;
  }

  confstr =  "digitalSignature: hu, keyEncipherment: hu, dataEncipherment: hu";
  if ((ex8 = X509V3_EXT_conf_nid(NULL, NULL, NID_key_usage, confstr)) == NULL) {
    PRXYerr(PRXYERR_F_PROXY_SIGN, PRXYERR_R_CLASS_ADD_EXT);
    goto err;
  }

  if (!sk_X509_EXTENSION_push(extensions, ex8)) {
    PRXYerr(PRXYERR_F_PROXY_SIGN,PRXYERR_R_CLASS_ADD_EXT);
    goto err;
  }

  kusg = true;

  /* vo extension */
  
  if (!voID.empty()) {
  
    if ((ex4 = CreateProxyExtension("vo", voID)) == NULL) {
      PRXYerr(PRXYERR_F_PROXY_SIGN,PRXYERR_R_CLASS_ADD_EXT);
      goto err;
    }
    
    if (!sk_X509_EXTENSION_push(extensions, ex4)) {
      PRXYerr(PRXYERR_F_PROXY_SIGN,PRXYERR_R_CLASS_ADD_EXT);
      goto err;
    }
    
    vo = true;
  }
  

  /* class_add extension */

#ifdef CLASS_ADD
  
  if (class_add_buf && class_add_buf_len > 0) {
    if ((ex2 = proxy_extension_class_add_create((void *)class_add_buf, class_add_buf_len)) == NULL) {
      PRXYerr(PRXYERR_F_PROXY_SIGN,PRXYERR_R_CLASS_ADD_EXT);
      goto err;
    }
    
    if (!sk_X509_EXTENSION_push(extensions, ex2)) {
      PRXYerr(PRXYERR_F_PROXY_SIGN,PRXYERR_R_CLASS_ADD_EXT);
      goto err;
    }
    
    classadd = true;
  }

#endif
  /* order extension */
 
  if (aclist && dataorder) {

    char *buffer = BN_bn2hex(dataorder);
    std::string tmp = std::string(buffer);
    OPENSSL_free(buffer);

    if ((ex6 = CreateProxyExtension("order", tmp)) == NULL) {
      PRXYerr(PRXYERR_F_PROXY_SIGN,PRXYERR_R_CLASS_ADD_EXT);
      goto err;
    }
     
    if (!sk_X509_EXTENSION_push(extensions, ex6)) {
      PRXYerr(PRXYERR_F_PROXY_SIGN,PRXYERR_R_CLASS_ADD_EXT);
      goto err;
    }
     
    order = true;
  }
  
  /* PCI extension */
  
  if(version==3) {

    std::string                         policy;
    unsigned char *                     der;
    int                                 derlen;
    unsigned char *                     pp;
    int                                 w;
    PROXYPOLICY *                       proxypolicy;
    PROXYCERTINFO *                     proxycertinfo;
    ASN1_OBJECT *                       policy_language;
    
    
    /* getting contents of policy file */
  
    std::ifstream fp;
    if(!policyfile.empty()) {
      fp.open(policyfile.c_str());
      if(!fp) {
        std::cerr << std::endl << "Error: can't open policy file" << std::endl;
        exit(1);
      }
      fp.unsetf(std::ios::skipws);
      char c;
      while(fp.get(c))
        policy += c;
    }
    
    /* setting policy language field */
    
    if(policylang.empty()) {
      if(policyfile.empty()) {
        policylang = IMPERSONATION_PROXY_OID;
        if(debug) std::cout << "No policy language specified, Gsi impersonation proxy assumed." << std::endl;
      }
      else {
        policylang = GLOBUS_GSI_PROXY_GENERIC_POLICY_OID;
        if(debug) std::cout << "No policy language specified with policy file, assuming generic." << std::endl;
      }
    }
    
    /* predefined policy language can be specified with simple name string */
    
    else if(policylang == IMPERSONATION_PROXY_SN)
      policylang = IMPERSONATION_PROXY_OID;
    else if(policylang == INDEPENDENT_PROXY_SN)
      policylang = INDEPENDENT_PROXY_OID;
    
    /* does limited prevale on others? don't know what does grid-proxy_init since if pl is given with
       limited options it crash */
    if(limit_proxy)
      policylang = LIMITED_PROXY_OID;

    OBJ_create((char *)policylang.c_str(), (char *)policylang.c_str(), (char *)policylang.c_str());
    
    if(!(policy_language = OBJ_nid2obj(OBJ_sn2nid(policylang.c_str())))) {
      PRXYerr(PRXYERR_F_PROXY_SIGN, PRXYERR_R_CLASS_ADD_OID);
      goto err;
    }
    
    /* proxypolicy */
    
    proxypolicy = PROXYPOLICY_new();
    if(policy.size()>0)
      PROXYPOLICY_set_policy(proxypolicy, (unsigned char *)policy.c_str(), policy.size());
    PROXYPOLICY_set_policy_language(proxypolicy, policy_language);

    /* proxycertinfo */
    
    proxycertinfo = PROXYCERTINFO_new();
    PROXYCERTINFO_set_proxypolicy(proxycertinfo, proxypolicy);
    if(pathlength>=0) {
      PROXYCERTINFO_set_path_length(proxycertinfo, pathlength);
    }
    
    /* 2der conversion */
    
    derlen = i2d_PROXYCERTINFO(proxycertinfo, NULL);
    der = (unsigned char *)malloc(derlen);
    pp = der;
    w = i2d_PROXYCERTINFO(proxycertinfo, &pp);
    
    std::string tmp = (char *)der;
    
    if ((ex7 = CreateProxyExtension("PROXYCERTINFO", tmp, true)) == NULL) {
      PRXYerr(PRXYERR_F_PROXY_SIGN, PRXYERR_R_CLASS_ADD_EXT);
      goto err;
    }
    
    if (!sk_X509_EXTENSION_push(extensions, ex7)) {
      PRXYerr(PRXYERR_F_PROXY_SIGN,PRXYERR_R_CLASS_ADD_EXT);
      goto err;
    }
    
  }
  
  if (proxy_sign(pcd->ucert,
                 pcd->upkey,
                 req,
                 &ncert,
                 hours*60*60 + minutes*60,
                 extensions,
                 limit_proxy,
                 version)) {
    goto err;
  }
  
  if ((bp = BIO_new(BIO_s_file())) != NULL)
    BIO_set_fp(bp, fpout, BIO_NOCLOSE);
  
  if (proxy_marshal_bp(bp, ncert, npkey, pcd->ucert, pcd->cert_chain))
    goto err;
  
  if(!quiet) std::cout << " Done" << std::endl;

  status = false;

 err:

  if (ncert)
    X509_free(ncert);
  if (bp)
    BIO_free(bp);
  if (fpout)
    fclose(fpout);
  if (extensions) {
    sk_X509_EXTENSION_pop_free(extensions, X509_EXTENSION_free);
    order = kusg = voms = classadd = file = vo = acs = info = false;
  }
  if(req) {
    X509_REQ_free(req);
  }
  if (kusg)
    X509_EXTENSION_free(ex8);
  if(npkey)
    EVP_PKEY_free(npkey);
  if (order)
    X509_EXTENSION_free(ex6);
  if (info)
    X509_EXTENSION_free(ex7);
  if (acs)
    X509_EXTENSION_free(ex5);
  if (voms)
    X509_EXTENSION_free(ex2);
  if (file)
    X509_EXTENSION_free(ex3);
  if (vo)
    X509_EXTENSION_free(ex4);
  if (classadd)
    X509_EXTENSION_free(ex1);
  
  return status;

}

X509_EXTENSION * Client::CreateProxyExtension(std::string name, std::string data, bool crit) {

  X509_EXTENSION *                    ex = NULL;
  ASN1_OBJECT *                       ex_obj = NULL;
  ASN1_OCTET_STRING *                 ex_oct = NULL;

  if(!(ex_obj = OBJ_nid2obj(OBJ_txt2nid((char *)name.c_str())))) {
    PRXYerr(PRXYERR_F_PROXY_SIGN,PRXYERR_R_CLASS_ADD_OID);
    goto err;
  }
  
  if(!(ex_oct = ASN1_OCTET_STRING_new())) {
    PRXYerr(PRXYERR_F_PROXY_SIGN,PRXYERR_R_CLASS_ADD_EXT);
    goto err;
  }
  
  ex_oct->data = (unsigned char *)data.c_str();
  ex_oct->length = data.size();
  
  if (!(ex = X509_EXTENSION_create_by_OBJ(NULL, ex_obj, crit, ex_oct))) {
    PRXYerr(PRXYERR_F_PROXY_SIGN,PRXYERR_R_CLASS_ADD_EXT);
    goto err;
  }
	
  //  ASN1_OCTET_STRING_free(ex_oct);
  //  ASN1_OBJECT_free(ex_obj);
  ex_oct = NULL;
	
  return ex;
  
 err:
  
  if (ex_oct)
    ASN1_OCTET_STRING_free(ex_oct);
  
  if (ex_obj)
    ASN1_OBJECT_free(ex_obj);
  
  return NULL;
  
}

bool Client::WriteSeparate() {

  if(aclist) {
    
    BIO * out = BIO_new(BIO_s_file());
    if(data.empty())
      BIO_write_filename(out, (char *)separate.c_str());
    else BIO_write_filename(out, (char *)(separate+".ac").c_str());
    
    while(*aclist)
      if(!PEM_ASN1_write_bio(((int (*)())i2d_AC), "ATTRIBUTE CERTIFICATE", out, (char *)*(aclist++), NULL, NULL, 0, NULL, NULL)) {
        if(!quiet) std::cout << "Unable to write to BIO" << std::endl;
        return false;;
      }
    
    BIO_free(out);
  
    if(data.empty())
      if(!quiet)
        std::cout << "Wrote ACs to " << separate << std::endl;
  }
  
  if(!data.empty()) {
    
    if(aclist) {
      if(!quiet)
        std:: cout << "Wrote ACs to " << separate+".ac" << std::endl;      
    }
    
    std::ofstream fs;
    fs.open((separate+".data").c_str());
    if (!fs) {
      std::cerr << "cannot open file" << std::endl;
      return false;
    }
    else {
      for(std::string::iterator pos = data.begin(); pos != data.end(); pos++)
        fs << *pos;
      fs.close();
    }
    
    if(!quiet)
      std::cout << "Wrote data to " << separate+".data" << std::endl;

  }

  return true;
}

bool Client::IncludeFile(std::string& filedata) {

  std::ifstream fp;
  fp.open(incfile.c_str());
  if(!fp) {
    std::cerr << std::endl << "Error: cannot opens file" << std::endl;
    return false;
  }
  fp.unsetf(std::ios::skipws);
  char c;
  while(fp.get(c))
    filedata += c;
  
  return true;
}

bool Client::Verify() {

  bool status = false;

  proxy_verify_ctx_init(&pvxd);
  proxy_verify_init(&pvd, &pvxd);
  pvxd.certdir = this->certdir;
  if (proxy_verify_cert_chain(pcd->ucert, pcd->cert_chain, &pvd)) {
    if(!quiet) std::cout << "verify OK" << std::endl; 
    return true;
  }
  else {
    std::cerr << "Error: verify failed." << std::endl;
    goto err;
  }
  
 err:
  
  Error();

  return status;

}

bool Client::Test() {

  ASN1_UTCTIME * asn1_time = ASN1_UTCTIME_new();
  X509_gmtime_adj(asn1_time, 0);
  time_t time_now = ASN1_UTCTIME_mktime(asn1_time);
  ASN1_UTCTIME_free(asn1_time);
  time_t time_after = ASN1_UTCTIME_mktime(X509_get_notAfter(pcd->ucert));
  time_t time_diff = time_after - time_now ;
  
  if (time_diff < 0) {
    if (!quiet) 
      std::cout << std::endl << "ERROR: Your certificate expired "
                << asctime(localtime(&time_after)) << std::endl;
    
    return 2;
  } 
  
  if (hours && time_diff < hours*60*60 + minutes*60) {
    if (!quiet) std::cout << std::endl << "Warning: your certificate and proxy will expire "
                          << asctime(localtime(&time_after))
                          << "which is within the requested lifetime of the proxy"
                          << std::endl;
    return 1;
  }
  
  if (!quiet)
  {
    time_t time_after_proxy;
    time_after_proxy = time_now + hours*60*60 + minutes*60;
    
    if (!quiet) std::cout << "Your proxy is valid until "
                          << asctime(localtime(&time_after_proxy)) << std::flush;
    
    return 0;
  }

  return 0;
}

bool Client::Retrieve(std::string buffer) {

  bool status =  false;

  if(buffer.empty())
    return status;

  AC ** actmplist = NULL;
  AC * ac;
  char *p, *pp;
  
  int len = buffer.size();
  pp = (char *)malloc(buffer.size());
  if (!pp)
    return false;

  pp = (char *)memcpy(pp, buffer.data(), buffer.size());
  p = pp;
  
  if((ac = d2i_AC(NULL, (unsigned char **)&p, len))) {
    actmplist = (AC **)listadd((char **)aclist, (char *)ac, sizeof(AC *));
    if (actmplist) {
      aclist = actmplist;
      (void)BN_lshift1(dataorder, dataorder);
      (void)BN_set_bit(dataorder, 0);
      status = true;
    }
    else {
      listfree((char **)aclist, (freefn)AC_free);
      goto err;
    }
  }
  
 err:

  free(pp);
  Error();
  return status;

}

bool Client::pcdInit() {

  int status = false;

  ERR_load_prxyerr_strings(0);
  SSLeay_add_ssl_algorithms();
  
  BIO * bio_err;
  if ((bio_err = BIO_new(BIO_s_file())) != NULL)
    BIO_set_fp(bio_err, stderr, BIO_NOCLOSE);

  if ((pcd = proxy_cred_desc_new()) == NULL)
    goto err;  
  
  pcd->type = CRED_TYPE_PERMANENT;
  
  if (noregen) {

    std::string oldoutfile = "";
    if(outfile)
      oldoutfile = outfile;

    bool modify = false;
    outfile = NULL;
    if (certfile == NULL && keyfile == NULL) 
      modify = true;
    if (proxy_get_filenames(pcd, 0, &cacertfile, &certdir, &outfile, &certfile, &keyfile))
      goto err;

    if (modify)
      certfile = keyfile = outfile;
    outfile = (oldoutfile.empty() ? NULL : const_cast<char *>(oldoutfile.c_str()));
    if ( proxy_get_filenames(pcd, 0, &cacertfile, &certdir, &outfile, &certfile, &keyfile))
      goto err;
  }
  else if (proxy_get_filenames(pcd, 0, &cacertfile, &certdir, &outfile, &certfile, &keyfile))
    goto err;
  
  // verify that user's certificate and key have the correct permissions

  struct stat stats;
  
  assert(stat("/data/valerio/.globus/usercert.pem", &stats) == 0);
  if (stats.st_mode & S_IXUSR || 
      stats.st_mode & S_IWGRP ||  
      stats.st_mode & S_IXGRP ||
      stats.st_mode & S_IWOTH ||
      stats.st_mode & S_IXOTH
      )  
  {
    std::cerr << std::endl << "ERROR: Couldn't find valid credentials to generate a proxy." << std::endl 
              << "Use --debug for further information." << std::endl;
    if(debug) {
      std::cout << "Wrong permissions on file: " << certfile << std::endl;
    }
    exit(1);
  }

  assert(stat(keyfile, &stats) == 0);
  if (stats.st_mode & S_IXUSR || 
      stats.st_mode & S_IRGRP ||  
      stats.st_mode & S_IWGRP ||  
      stats.st_mode & S_IXGRP ||
      stats.st_mode & S_IRGRP ||  
      stats.st_mode & S_IWOTH ||
      stats.st_mode & S_IXOTH)  
  {
    std::cerr << std::endl << "ERROR: Couldn't find valid credentials to generate a proxy." << std::endl 
              << "Use --debug for further information." << std::endl;
    if(debug) {
      std::cout << "Wrong permissions on file: " << keyfile << std::endl;
    }
    exit(1);
  }
  
  if(debug) std::cout << "Files being used:" << std::endl 
		      << " CA certificate file: " << (cacertfile ? cacertfile : "none") << std::endl
		      << " Trusted certificates directory : " << (this->certdir ? this->certdir : "none") << std::endl
		      << " Proxy certificate file : " << (this->outfile ? this->outfile : "none") << std::endl
		      << " User certificate file: " << (this->certfile ? this->certfile : "none") << std::endl
		      << " User key file: " << (this->keyfile ? this->keyfile : "none") << std::endl;
  
  if (debug)
    std::cout << "Output to " << outfile << std::endl;
  
  if (this->certdir)
    pcd->certdir = strdup(this->certdir);

  if (!strncmp(this->certfile, "SC:", 3))
    EVP_set_pw_prompt("Enter card pin:");
  else
    EVP_set_pw_prompt(const_cast<char *>("Enter GRID pass phrase for this identity:"));
  
  if(proxy_load_user_cert(pcd, this->certfile, pw_cb, NULL))
    goto err;
  
  if(!quiet) {
    char * s = NULL;
    s = X509_NAME_oneline(X509_get_subject_name(pcd->ucert),NULL,0);
    std::cout << "Your identity: " << s << std::endl;
    free(s);
  }
  
  EVP_set_pw_prompt("Enter GRID pass phrase:");
  
  if (!strncmp(this->keyfile, "SC:", 3))
    EVP_set_pw_prompt("Enter card pin:");

  if (proxy_load_user_key(pcd, this->keyfile, pw_cb, NULL))
    goto err;
  
  if (strncmp(this->certfile, "SC:", 3) && !strcmp(this->certfile, this->keyfile)) {
    if (pcd->cert_chain == NULL)
      pcd->cert_chain = sk_X509_new_null();
    if (proxy_load_user_proxy(pcd->cert_chain, this->certfile, NULL) < 0)
      goto err;
  } 
  
  status = true;
  
 err:

  if (bio_err)
    BIO_free(bio_err);
  Error();
  return status;
  
}

void Client::Error() {

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

static bool isAC(std::string data)
{
  char *p, *pp;
  bool res = false;
  AC *ac = NULL;
  int len = data.size();

  pp = (char *)malloc(len);

  if (pp) {
    pp = (char *)memcpy(pp, data.data(), len);
    p = pp;
    ac = d2i_AC(NULL, (unsigned char **)&p, len);
    if (ac)
      res = true;
    AC_free(ac);
    free(pp);
  }

  return res;
}
