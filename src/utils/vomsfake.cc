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
#include "replace.h"

#include "options.h"

#include <iostream>
#include <fstream>
#include <sstream>
#include <algorithm>

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
}

#include <voms_api.h>

#include "vomsfake.h"
#include "ccwrite.h"

extern "C" {

#include "proxycertinfo.h"

}

extern int AC_Init();

#include "init.h"

const std::string SUBPACKAGE      = "voms-proxy-fake";

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
std::vector<std::string> targets;


int main(int argc, char** argv) {

  struct rlimit newlimit = {0,0};
  if (setrlimit(RLIMIT_CORE, &newlimit) != 0)
    exit(1);

  if (AC_Init()) {
    Fake v(argc, argv);
    v.Run();

    return 0;
  }
  return 1;
}

Fake::Fake(int argc, char ** argv) :   confile(CONFILENAME), 
                                       separate(""), uri(""),bits(512),
                                       hours(12), limit_proxy(false),
                                       vomslife(-1), proxyver(0),
                                       pathlength(1), verify(false), version(0),
#ifdef CLASS_ADD
                                       classs_add_buf(NULL),
                                       class_add_buf_len(0),
#endif					   
                                       pcd(NULL), aclist(NULL), voID(""),
                                       hostcert(""), hostkey(""),
                                       newformat(false)
{
  
  bool progversion = false;
  std::string crtdir;
  std::string crtfile;
  std::string kfile;
  std::string ofile;
  std::vector<std::string> order;
  bool pwstdin = false;

  if (strrchr(argv[0],'/'))
    program = strrchr(argv[0],'/') + 1;
  else
    program = argv[0];
  
  /* usage message */

  static char *LONG_USAGE = \
    "\n" \
    "    Options\n" \
    "    -help, -usage                  Displays usage\n" \
    "    -version                       Displays version\n" \
    "    -debug                         Enables extra debug output\n" \
    "    -quiet, -q                     Quiet mode, minimal output\n" \
    "    -verify                        Verifies certificate to make proxy for\n" \
    "    -pwstdin                       Allows passphrase from stdin\n" \
    "    -limited                       Creates a limited proxy\n" \
    "    -hours H                       Proxy is valid for H hours (default:12)\n" \
    "    -bits                          Number of bits in key {512|1024|2048|4096}\n" \
    "    -cert     <certfile>           Non-standard location of user certificate\n" \
    "    -key      <keyfile>            Non-standard location of user key\n" \
    "    -certdir  <certdir>            Non-standard location of trusted cert dir\n" \
    "    -out      <proxyfile>          Non-standard location of new proxy cert\n" \
    "    -voms <voms>                   Specify voms server. :command is optional.\n" \
    "    -uri <uri>                     Specifies the <hostname>:<port> of the fake server.\n" \
    "    -target <hostname>             Targets the AC against a specific hostname.\n" \
    "    -vomslife <H>                  Try to get a VOMS pseudocert valid for H hours.\n" \
    "    -include <file>                Include the contents of the specified file.\n" \
    "    -conf <file>                   Read options from <file>.\n" \
    "    -policy <policyfile>           File containing policy to store in the ProxyCertInfo extension.\n" \
    "    -pl, -policy-language <oid>    OID string for the policy language.\n" \
    "    -policy-language <oid>         OID string for the policy language.\n" \
    "    -path-length <l>               Allow a chain of at most l proxies to be generated from this ones.\n" \
    "    -globus                        Globus version.\n" \
    "    -proxyver                      Version of proxy certificate.\n" \
    "    -noregen                       Doesn't regenerate a new proxy for the connection.\n" \
    "    -separate <file>               Saves the informations returned by the server on file <file>.\n" \
    "    -hostcert <file>               Fake host certificate.\n" \
    "    -hostkey <file>                Fake host private key.\n" \
    "    -fqan <string>                 String to include in the AC as the granted FQAN.\n" \
    "    -newformat                     Creates ACs according to the new format.\n" \
    "\n";

  set_usage(LONG_USAGE);

  /* parse command-line option */

  struct option opts[] = {
    {"help",            0, NULL,                OPT_HELP},
    {"usage",           0, NULL,                OPT_HELP},
    {"version",         0, (int *)&progversion, OPT_BOOL},
    {"cert",            1, (int *)&crtfile,     OPT_STRING},
    {"certdir",         1, (int *)&crtdir,      OPT_STRING},
    {"out",             1, (int *)&ofile,       OPT_STRING},
    {"key",             1, (int *)&kfile,       OPT_STRING},
    {"include",         1, (int *)&incfile,     OPT_STRING},
    {"hours",           1,        &hours,       OPT_NUM},
    {"vomslife",        1,        &vomslife,    OPT_NUM},
    {"bits",            1,        &bits,        OPT_NUM},
    {"debug",           0, (int *)&debug,       OPT_BOOL},
    {"limited",         0, (int *)&limit_proxy, OPT_BOOL},
    {"verify",          0, (int *)&verify,      OPT_BOOL},
    {"q",               0, (int *)&quiet,       OPT_BOOL},
    {"quiet",           0, (int *)&quiet,       OPT_BOOL},
    {"pwstdin",         0, (int *)&pwstdin,     OPT_BOOL},
    {"conf",            1, NULL,                OPT_CONFIG},
    {"voms",            1, (int *)&voms,        OPT_STRING},
    {"target",          1, (int *)&targets,     OPT_MULTI},
    {"globus",          1,        &version,     OPT_NUM},
    {"proxyver",        1,        &proxyver,    OPT_NUM},
    {"policy",          1, (int *)&policyfile,  OPT_STRING},
    {"policy-language", 1, (int *)&policylang,  OPT_STRING},
    {"pl",              1, (int *)&policylang,  OPT_STRING},
    {"path-length",     1,        &pathlength,  OPT_NUM},
    {"separate",        1, (int *)&separate,    OPT_STRING},
    {"uri",             1, (int *)&uri,         OPT_STRING},
    {"hostcert",        1, (int *)&hostcert,    OPT_STRING},
    {"hostkey",         1, (int *)&hostkey,     OPT_STRING},
    {"fqan",            1, (int *)&fqans,       OPT_MULTI},
    {"newformat",       1, (int *)&newformat,   OPT_BOOL},
#ifdef CLASS_ADD
    {"classadd",        1, (int *)class_add_buf,OPT_STRING},
#endif
    {0, 0, 0, 0}
  };

  if (!getopts(argc, argv, opts))
    exit(1);
  
  
  if(debug)
    quiet = false;
  
  /* show version and exit */
  
  if (progversion) {
    std::cout << SUBPACKAGE << "\nVersion: " << VERSION << std::endl;
    std::cout << "Compiled: " << __DATE__ << " " << __TIME__ << std::endl;
    exit(0);
  }

  if (hostcert.empty() || hostkey.empty()) {
    std::cout  << "You must specify an host certificate!" << std::endl;
    exit(1);
  }

  /* set globus version */

  version = globus(version);
  if (version == 0) {
    version = 22;
    if (debug) 
      std::cout << "Unable to discover Globus version: trying for 2.2" << std::endl;
  }
  else 
    if (debug) 
      std::cout << "Detected Globus version: " << version << std::endl;
  
  /* set proxy version */
  
  if (proxyver!=2 && proxyver!=3 && proxyver!=0) {
    std::cerr << "Error: proxyver must be 2 or 3" << std::endl;
    exit(1);
  }
  else if (proxyver==0) {
    if (debug)
      std::cout << "Unspecified proxy version, settling on Globus version: ";
    if (version<30)
      proxyver = 2;
    else 
      proxyver = 3;
    if (debug)
      std::cout << proxyver << std::endl;
  }
  
  /* PCI extension option */ 
  
  if (proxyver==3) {
    if (!policylang.empty())
      if (policyfile.empty()) {
        std::cerr << "Error: if you specify a policy language you also need to specify a policy file" << std::endl;
        exit(1);
      }
  }
  
  if (proxyver==3) {
    if(debug) 
      std::cout << "PCI extension info: " << std::endl << " Path length: " << pathlength << std::endl;

    if (policylang.empty()) {
      if (debug) 
        std::cout << " Policy language not specified." << policylang << std::endl;
    }
    else if (debug) 
      std::cout << " Policy language: " << policylang << std::endl;

    if (policyfile.empty()) {
      if (debug) 
        std::cout << " Policy file not specified." << std::endl;
    }
    else if (debug) 
      std::cout << " Policy file: " << policyfile << std::endl;
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
  
  /* certficate duration option */
  
  if(!(hours>0)) {
    std::cerr << "Error: duration must be positive." << std::endl;
    exit(1);
  }
  
  if (vomslife == -1)
    vomslife = hours;
  
  if(!(vomslife>0)) {
    std::cerr << "Error: duration of AC must be positive." << std::endl;
    exit(1);
  }

  /* allow password form stdin */

  if(pwstdin)
    pw_cb = (int (*)())(pwstdin_callback);

  /* with --debug prints configuration files used */

  if(debug) {
    std::cout << "Using configuration directory " << confile << std::endl;
  }

  /* file used */
  
  cacertfile = NULL;
  certdir  = (crtdir.empty()  ? NULL : const_cast<char *>(crtdir.c_str()));
  outfile  = (ofile.empty()   ? NULL : const_cast<char *>(ofile.c_str()));
  certfile = (crtfile.empty() ? NULL : const_cast<char *>(crtfile.c_str()));
  keyfile  = (kfile.empty()   ? NULL : const_cast<char *>(kfile.c_str()));


  /* prepare proxy_cred_desc */

  if(!pcdInit())
    exit(3);

}

Fake::~Fake() {

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
  
  OBJ_cleanup();

}

bool Fake::Run() {

  std::string filedata;

  /* set output file and environment */
  
  char * oldenv = getenv("X509_USER_PROXY");
  
  if(!noregen) {
    std::stringstream tmpproxyname;
    tmpproxyname << "/tmp/tmp_x509up_u" << getuid() << "_" << getpid();
    proxyfile = tmpproxyname.str();
    setenv("X509_USER_PROXY", proxyfile.c_str(), 1);
  }
  
  /* contacts servers for each vo */

  Retrieve();
 
  /* set output file and environment */
  
  proxyfile = outfile;
  setenv("X509_USER_PROXY", proxyfile.c_str(), 1);  
  
  /* include file */
  
  if (!incfile.empty())
    if(!IncludeFile(filedata))
      if(!quiet) std::cout << "Wasn't able to include file " << incfile << std::endl;;
  
  /* with separate write info to file and exit */
  
  if (!separate.empty() && aclist) {
    if(!WriteSeparate())
      if(!quiet) std::cout << "Wasn't able to write to " << separate << std::endl;
    exit(0);
  }
  
  /* create a proxy containing the data retrieved from VOMS servers */
  
  if(!quiet) std::cout << "Creating proxy " << std::flush; 
  if(debug) std::cout << "to " << proxyfile << " " << std::flush;
  if(CreateProxy("", filedata, aclist, NULL, proxyver)) {
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
  
  /* assure user certificate is not expired or going to, else ad but still create proxy */
  
  Test();
  
  return true;

 err:
  
  Error();

  return false;

}

bool Fake::CreateProxy(std::string data, std::string filedata, AC ** aclist, BIGNUM * dataorder, int version) {

  bool status = true;
  
  X509 * ncert = NULL;
  EVP_PKEY * npkey;
  X509_REQ * req;
  BIO * bp = NULL;
  STACK_OF(X509_EXTENSION) * extensions = NULL;
  X509_EXTENSION *ex1 = NULL, *ex2 = NULL, *ex3 = NULL, *ex4 = NULL, *ex5 = NULL, *ex6 = NULL, *ex7 = NULL;
  bool voms, classadd, file, vo, acs, order, info;
  order = acs = vo = voms = classadd = file = false;
  
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
  
  /* order extension */

  if (dataorder) {
    
    std::string tmp = std::string(BN_bn2hex(dataorder));
    
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
  
  /* PCI extension */
  
  if (version==3) {

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
    if (!policyfile.empty()) {
      fp.open(policyfile.c_str());
      if (!fp) {
        std::cerr << std::endl << "Error: can't open policy file" << std::endl;
        exit(1);
      }
      fp.unsetf(std::ios::skipws);
      char c;
      while(fp.get(c))
        policy += c;
    }
    
    /* setting policy language field */
    
    if (policylang.empty()) {
      if (policyfile.empty()) {
        policylang = IMPERSONATION_PROXY_OID;
        if (debug) 
          std::cout << "No policy language specified, Gsi impersonation proxy assumed." << std::endl;
      }
      else {
        policylang = GLOBUS_GSI_PROXY_GENERIC_POLICY_OID;
        if (debug) 
          std::cout << "No policy language specified with policy file, assuming generic." << std::endl;
      }
    }
    
    /* predefined policy language can be specified with simple name string */
    
    else if (policylang == IMPERSONATION_PROXY_SN)
      policylang = IMPERSONATION_PROXY_OID;
    else if (policylang == INDEPENDENT_PROXY_SN)
      policylang = INDEPENDENT_PROXY_OID;
    
    /* does limited prevale on others? don't know what does grid-proxy_init since if pl is given with
       limited options it crash */
    if (limit_proxy)
      policylang = LIMITED_PROXY_OID;

    OBJ_create((char *)policylang.c_str(), (char *)policylang.c_str(), (char *)policylang.c_str());
    
    if (!(policy_language = OBJ_nid2obj(OBJ_sn2nid(policylang.c_str())))) {
      PRXYerr(PRXYERR_F_PROXY_SIGN, PRXYERR_R_CLASS_ADD_OID);
      goto err;
    }
    
    /* proxypolicy */
    
    proxypolicy = PROXYPOLICY_new();
    if (policy.size()>0)
      PROXYPOLICY_set_policy(proxypolicy, (unsigned char *)policy.c_str(), policy.size());
    PROXYPOLICY_set_policy_language(proxypolicy, policy_language);

    /* proxycertinfo */
    
    proxycertinfo = PROXYCERTINFO_new();
    PROXYCERTINFO_set_proxypolicy(proxycertinfo, proxypolicy);
    if (pathlength>=0) {
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
  
  if (proxy_sign(pcd->ucert, pcd->upkey, req, &ncert, hours*60*60,
                 extensions, limit_proxy, version)) {
    goto err;
  }
  
  if ((bp = BIO_new(BIO_s_file())) != NULL)
    BIO_set_fp(bp, fpout, BIO_NOCLOSE);
  
  if (proxy_marshal_bp(bp, ncert, npkey, pcd->ucert, pcd->cert_chain))
    goto err;
  
  if (!quiet) std::cout << " Done" << std::endl << std::flush;

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
    voms = classadd = file = vo = acs = order = info = false;
  }
  if (req) {
    X509_REQ_free(req);
  }
  if (npkey)
    EVP_PKEY_free(npkey);
  if (info)
    X509_EXTENSION_free(ex7);
  if (order)
    X509_EXTENSION_free(ex6);
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

X509_EXTENSION * Fake::CreateProxyExtension(std::string name, std::string data, bool crit) {

  X509_EXTENSION *                    ex = NULL;
  ASN1_OBJECT *                       ex_obj = NULL;
  ASN1_OCTET_STRING *                 ex_oct = NULL;

  if (!(ex_obj = OBJ_nid2obj(OBJ_txt2nid((char *)name.c_str())))) {
    PRXYerr(PRXYERR_F_PROXY_SIGN,PRXYERR_R_CLASS_ADD_OID);
    goto err;
  }
  
  if (!(ex_oct = ASN1_OCTET_STRING_new())) {
    PRXYerr(PRXYERR_F_PROXY_SIGN,PRXYERR_R_CLASS_ADD_EXT);
    goto err;
  }
  
  ex_oct->data = (unsigned char *)data.c_str();
  ex_oct->length = data.size();
  
  if (!(ex = X509_EXTENSION_create_by_OBJ(NULL, ex_obj, crit, ex_oct))) {
    PRXYerr(PRXYERR_F_PROXY_SIGN,PRXYERR_R_CLASS_ADD_EXT);
    goto err;
  }
	
  ex_oct = NULL;
	
  return ex;
  
 err:
  
  if (ex_oct)
    ASN1_OCTET_STRING_free(ex_oct);
  
  if (ex_obj)
    ASN1_OBJECT_free(ex_obj);
  
  return NULL;
  
}

bool Fake::WriteSeparate() 
{
  if (aclist) {
    BIO * out = BIO_new(BIO_s_file());
    BIO_write_filename(out, (char *)separate.c_str());
    
    while(*aclist)
      if (!PEM_ASN1_write_bio(((int (*)())i2d_AC), "ATTRIBUTE CERTIFICATE", out, (char *)*(aclist++), NULL, NULL, 0, NULL, NULL)) {
        if (!quiet) 
          std::cout << "Unable to write to BIO" << std::endl;
        return false;
      }
    
    BIO_free(out);
  
    if (!quiet)
      std::cout << "Wrote ACs to " << separate << std::endl;
    
  }

  return true;
}

bool Fake::IncludeFile(std::string& filedata) {

  std::ifstream fp;
  fp.open(incfile.c_str());
  if (!fp) {
    std::cerr << std::endl << "Error: cannot opens file" << std::endl;
    return false;
  }
  fp.unsetf(std::ios::skipws);
  char c;
  while(fp.get(c))
    filedata += c;
  
  return true;
}

void Fake::Test() {

  ASN1_UTCTIME * asn1_time = ASN1_UTCTIME_new();
  X509_gmtime_adj(asn1_time, 0);
  time_t time_now = ASN1_UTCTIME_mktime(asn1_time);
  time_t time_after = ASN1_UTCTIME_mktime(X509_get_notAfter(pcd->ucert));
  time_t time_diff = time_after - time_now ;

  if (!quiet) {
    if (time_diff < 0)
      std::cout << std::endl << "Error: your certificate expired "
                << asctime(localtime(&time_after)) << std::endl << std::flush;
    else if (hours && time_diff < hours*60*60)
      std::cout << "Warning: your certificate and proxy will expire "
                << asctime(localtime(&time_after))
                << "which is within the requested lifetime of the proxy"
                << std::endl << std::flush;
  
    time_t time_after_proxy;
    
    if (hours) 
      time_after_proxy = time_now + hours*60*60;
    else 
      time_after_proxy = time_after;
    
    std::cout << "Your proxy is valid until "
              << asctime(localtime(&time_after_proxy)) << std::endl << std::flush;
  }
}

bool Fake::Retrieve() 
{
  AC **actmplist = NULL;
  AC *ac = NULL;
  int res = 0;
  BIO *hcrt = BIO_new(BIO_s_file()), 
      *hckey = BIO_new(BIO_s_file()),
      *owncert = BIO_new(BIO_s_file());
  X509 *hcert = NULL, *holder = NULL;
  EVP_PKEY *hkey = NULL;

  // generic attributes TO BE FILLED
  std::vector<std::string> attributes;

  if (hcrt && hckey && owncert) {
    if ((BIO_read_filename(hcrt, hostcert.c_str()) > 0) &&
        (BIO_read_filename(hckey, hostkey.c_str()) > 0) &&
        (BIO_read_filename(owncert, certfile) > 0)) {
      hcert = PEM_read_bio_X509(hcrt, NULL, 0, NULL);
      holder = PEM_read_bio_X509(owncert, NULL, 0, NULL);
      hkey = PEM_read_bio_PrivateKey(hckey, NULL, 0, NULL);

      if (hcert && hkey) {
        ac = AC_new();
        if (ac)
          res = createac(holder, NULL, hcert, hkey, (BIGNUM *)(BN_value_one()), fqans, 
                         targets, attributes, &ac, voms, uri, hours*3600, !newformat);
      }
    }
  }

  if (!res)
    actmplist = (AC **)listadd((char **)aclist, (char *)ac, sizeof(AC *));
  if (actmplist)
    aclist = actmplist;

  X509_free(hcert);
  X509_free(holder);
  EVP_PKEY_free(hkey);
  BIO_free(hcrt);
  BIO_free(hckey);
  BIO_free(owncert);

  if (!actmplist) {
    AC_free(ac);
    listfree((char **)aclist, (freefn)AC_free);

    Error();
    return false;
  }

  return true;
}

bool Fake::pcdInit() {

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
    if (outfile)
      oldoutfile = outfile;

    bool modify = false;
    outfile = NULL;
    if (certfile == NULL && keyfile == NULL) 
      modify = true;

    if (proxy_get_filenames(pcd, 0, &cacertfile, &certdir, &outfile, &certfile, &keyfile))
      goto err;

    //    if (modify)
    //      certfile = keyfile = outfile;
    outfile = (oldoutfile.empty() ? NULL : const_cast<char *>(oldoutfile.c_str()));

    if ( proxy_get_filenames(pcd, 0, &cacertfile, &certdir, &outfile, &certfile, &keyfile))
      goto err;
  }
  else if (proxy_get_filenames(pcd, 0, &cacertfile, &certdir, &outfile, &certfile, &keyfile))
    goto err;
  
  if (debug) std::cout << "Files being used:" << std::endl 
                       << " CA certificate file: " << (cacertfile ? cacertfile : "none") << std::endl
                       << " Trusted certificates directory : " << (this->certdir ? this->certdir : "none") << std::endl
                       << " Proxy certificate file : " << (this->outfile ? this->outfile : "none") << std::endl
                       << " User certificate file: " << (this->certfile ? this->certfile : "none") << std::endl
                       << " User key file: " << (this->keyfile ? this->keyfile : "none") << std::endl << std::flush;
  
  if (debug)
    std::cout << "Output to " << outfile << std::endl << std::flush;
  
  if (this->certdir)
    pcd->certdir = strdup(this->certdir);

  if (!strncmp(this->certfile, "SC:", 3))
    EVP_set_pw_prompt("Enter card pin:");
  else
    EVP_set_pw_prompt(const_cast<char *>("Enter GRID pass phrase for this identity:"));
  
  if (proxy_load_user_cert(pcd, this->certfile, pw_cb, NULL))
    goto err;
  
  if (!quiet) {
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

  Error();
  return status;
  
}

void Fake::Error() {

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
                  << file << ":" << line << dat << std::endl << std::flush;
      else
        std::cerr << ERR_reason_error_string(l) << dat
                  << "\nFunction: " << ERR_func_error_string(l) << std::endl;
    }
    
    free(dat);
  }

}
