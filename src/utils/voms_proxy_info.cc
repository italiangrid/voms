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

/**********************************************************************
                             Include header files
**********************************************************************/
#include "config.h"
#include "replace.h"

extern "C" {
#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

#include "openssl/buffer.h"
#include "openssl/crypto.h"
#include "openssl/objects.h"
#include "openssl/asn1.h"
#include "openssl/evp.h"
#include "openssl/x509.h"
#include "openssl/pem.h"
#include "openssl/ssl.h"
#include "openssl/rsa.h"
#include "openssl/conf.h"

#ifdef USE_PKCS11
#include "scutils.h"
#endif
#include "sslutils.h"
#include "newformat.h"
#include "listfunc.h"
#include "myproxycertinfo.h"
}

extern int AC_Init(void);

#include "data.h"
#include "options.h"

#include <string>
#include "voms_api.h"

extern const X509V3_EXT_METHOD v3_key_usage;

#include <vector>
#include <iostream>
#include <iomanip>
#include <fstream>
#include <iterator>
#include <algorithm>

bool debug = false;
bool quiet = false;

const std::string SUBPACKAGE      = "voms-proxy-info";

/**********************************************************************
                       Define module specific variables
**********************************************************************/

static bool test_proxy();

static bool print(X509 *cert, STACK_OF(X509) *chain, vomsdata &vd);
static STACK_OF(X509) *load_chain_from_file(char *certfile);
static time_t stillvalid(ASN1_TIME *ctm);
static const char *proxy_type(X509 *cert);
static std::string getKeyUsage(X509 *cert);

std::string program;

#ifdef WIN32
static int getuid() { return 0;}
#endif

static std::string file;

static bool        progversion = false;

static bool        subject = false;
static bool        issuer = false;
static bool        identity = false;
static bool        type = false;
static bool        timeleft = false;
static bool        strength = false;
static bool        all = false;
static bool        path = false;
static bool        text = false;

static bool        vo = false;
static bool        fqan = false;
static bool        acsubject = false;
static bool        acissuer = false;
static bool        actimeleft = false;

static bool        defaultinfo = false;

static bool        exists = false;
static std::string valid;
static int         hours = 0;
static int         minutes = 0;
static int         bits        = 0;
static std::vector<std::string> acexists;
static bool        dochain = false;

static bool        serial = false;

static bool        dont_verify_ac = false;
static bool        targets = false;
static bool        included = false;
static bool        printuri = false;
static bool        keyusage = false;

int
main(int argc, char **argv)
{

  InitProxyCertInfoExtension(1);

  if (strrchr(argv[0],'/'))
    program = strrchr(argv[0],'/') + 1;
  else
    program = argv[0];

  static std::string LONG_USAGE = 
    "\n\n"
    "Syntax: voms-proxy-info [-help][-file proxyfile][-subject][...][-exists [-hours H][-bits B][-valid H:M]]\n\n"
    "   Options\n"
    "   -help, -usage             Displays usage\n"
    "   -version                  Displays version\n"
    "   -debug                    Displays debugging output\n"
    "   -file <proxyfile>         Non-standard location of proxy\n"
    "   -dont-verify-ac           Skips AC verification\n"
    "   [printoptions]            Prints information about proxy and attribute certificate\n"
    "   -exists [options]         Returns 0 if valid proxy exists, 1 otherwise\n"
    "   -acexists <voname>        Returns 0 if AC exists corresponding to voname, 1 otherwise\n"
    "   -conf <name>              Read options from file <name>\n"
    "   -included                 Print included file\n"
    "\n"
    "   [printoptions]\n"
    "      -chain                Prints information about the whol proxy chain (CA excluded)\n"
    "      -subject              Distinguished name (DN) of proxy subject\n"
    "      -issuer               DN of proxy issuer (certificate signer)\n"
    "      -identity             DN of the identity represented by the proxy\n"
    "      -type                 Type of proxy (full or limited)\n"
    "      -timeleft             Time (in seconds) until proxy expires\n"
    "      -strength             Key size (in bits)\n"
    "      -all                  All proxy options in a human readable format\n"
    "      -text                 All of the certificate\n"
    "      -path                 Pathname of proxy file\n"
    "      -vo                   Vo name\n"
    "      -fqan                 Attribute in FQAN format"
    "      -acsubject            Distinguished name (DN) of AC subject\n"
    "      -acissuer             DN of AC issuer (certificate signer)\n"
    "      -actimeleft           Time (in seconds) until AC expires\n"
    "      -serial               AC serial number \n"
    "      -uri                  Server URI\n"
    "      -keyusage             Print content of KeyUsage extension.\n"
    "\n"
    "   [options to -exists]      (if none are given, H = B = 0 are assumed)\n"
    "      -valid H:M            time requirement for proxy to be valid\n"
    "      -hours H              time requirement for proxy to be valid (deprecated, use -valid instead)\n"
    "      -bits  B              strength requirement for proxy to be valid\n"
    "\n";
  
  set_usage(LONG_USAGE);

  struct option opts[] = {
    {"help",        0, NULL,                OPT_HELP},
    {"usage",       0, NULL,                OPT_HELP},
    {"version",     0, (int *)&progversion, OPT_BOOL},
    {"debug",       0, (int *)&debug,       OPT_BOOL},
    {"file",        1, (int *)&file,        OPT_STRING},
    {"exists",      1, (int *)&exists,      OPT_BOOL},
    {"acexists",    1, (int *)&acexists,    OPT_MULTI},
    {"chain",       0, (int *)&dochain,     OPT_BOOL},
    {"conf",        1, NULL,                OPT_CONFIG},
    
    {"subject",     1, (int *)&subject,     OPT_BOOL},
    {"issuer",      1, (int *)&issuer,      OPT_BOOL},
    {"identity",    1, (int *)&issuer,      OPT_BOOL},
    {"type",        1, (int *)&type,        OPT_BOOL},
    {"timeleft",    1, (int *)&timeleft,    OPT_BOOL},
    {"strength",    1, (int *)&strength,    OPT_BOOL},
    {"path",        1, (int *)&path,        OPT_BOOL},
    {"all",         1, (int *)&all,         OPT_BOOL},
    {"text",        1, (int *)&text,        OPT_BOOL},
    {"vo",          1, (int *)&vo,          OPT_BOOL},
    {"fqan",        1, (int *)&fqan,        OPT_BOOL},
    {"acsubject",   1, (int *)&acsubject,   OPT_BOOL},
    {"acissuer",    1, (int *)&acissuer,    OPT_BOOL},
    {"actimeleft",  1, (int *)&actimeleft,  OPT_BOOL},
    {"serial",      1, (int *)&serial,      OPT_BOOL},

    {"valid",       1, (int *)&valid,       OPT_STRING},
    {"bits",        1, &bits,               OPT_NUM},
    {"hours",       1, &hours,              OPT_NUM},

    {"dont-verify-ac", 0, (int *)&dont_verify_ac, OPT_BOOL},
    {"targets",        0, (int *)&targets,        OPT_BOOL},
    {"included-file",  0, (int *)&included,       OPT_BOOL},
    {"uri",            0, (int *)&printuri,       OPT_BOOL},
    {"keyusage",       0, (int *)&keyusage,       OPT_BOOL},
    {0, 0, 0, 0}
  };

  if (!getopts(argc, argv, opts))
    exit(1);

  if (progversion) {
    std::cout << SUBPACKAGE << "\nVersion: " << VERSION << std::endl;
    std::cout << "Compiled: " << __DATE__ << " " << __TIME__ << std::endl;
    exit(0);
  }

  if (getenv("VOMS_PROXY_INFO_DONT_VERIFY_AC") != NULL) {
      dont_verify_ac = true;
  }

  AC_Init();

  if(!subject && 
     !issuer && 
     !type && 
     !timeleft && 
     !strength && 
     !path && 
     !text &&
     !vo && 
     !fqan && 
     !acsubject && 
     ! acissuer && 
     !actimeleft && 
     !serial && 
     !exists && 
     !targets &&
     !included &&
     !printuri &&
     acexists.empty())
    defaultinfo = true;

  // exists .....

  if(exists) {
    if(!valid.empty()) {
      /* parse valid option */
      std::string::size_type pos = valid.find(':');
      if (pos != std::string::npos && pos > 0) {
        if (hours==0)	{
          hours   = atoi(valid.substr(0, pos).c_str());
          minutes = atoi(valid.substr(pos+1).c_str());
        }
      }
      else 
        std::cerr << "value must be in the format: H:M" << std::endl;
      if (minutes < 0 || minutes >60)
        std::cerr << "specified minutes must be in the range 0-60" << std::endl;
    }
  }
  
  return !test_proxy();
}

int numbits(X509 *cert)
{
  EVP_PKEY *key = X509_extract_key(cert);
  int bits = 8 * EVP_PKEY_size(key);
  EVP_PKEY_free(key);
  return bits;
}

static char *findlast(char *haystack, char *needle)
{
  char *point = strstr(haystack, needle);
  char *tmp = point;

  while (tmp) {
    tmp = strstr(tmp+1, needle);
    if (tmp)
      point = tmp;
  }

  return point;
}

static const char *proxy_type(X509 *cert)
{
  char *buffer = X509_NAME_oneline(X509_get_subject_name(cert), NULL, 0);
  char *point1 = findlast(buffer,"CN=proxy");
  char *point2 = findlast(buffer,"CN=limited proxy");

  OPENSSL_free(buffer);

  /*
   * check whether "proxy" or "limited proxy" came last
   */
  if (point1 > point2)
      return "proxy";

  if (point2 > point1)
      return "limited proxy";

  int nidv3 = OBJ_txt2nid(PROXYCERTINFO_V3);
  int nidv4 = OBJ_txt2nid(PROXYCERTINFO_V4);

  int indexv3 = X509_get_ext_by_NID(cert, nidv3, -1);
  int indexv4 = X509_get_ext_by_NID(cert, nidv4, -1);

  if (indexv4 != -1)
    return "RFC compliant proxy";

  if (indexv3 != -1)
    return "GT3-style proxy";

  return "unknown";
}

/*
 * Function:
 *   test_proxy()
 *
 */
static bool
test_proxy()
{
  char *ccaf;
  char *cd;
  char *of;
  char *inof;
  char *cf;
  char *kf;
  bool res = false;
  BIO *bio_err;
  proxy_cred_desc *pcd;
  BIO  *in = NULL;
  X509 *x  = NULL;
  STACK_OF(X509) *chain = NULL;

#ifdef WIN32
  CRYPTO_malloc_init();
#endif

  ERR_load_prxyerr_strings(0);
  SSLeay_add_ssl_algorithms();

  EVP_set_pw_prompt("Enter GRID pass phrase:");

  if ((bio_err=BIO_new(BIO_s_file())) != NULL)
    BIO_set_fp(bio_err,stderr,BIO_NOCLOSE);

  if ((pcd = proxy_cred_desc_new()) == NULL)
    goto err;

  pcd->type = CRED_TYPE_PERMANENT;

  /*
   * These 5 const_cast are allowed because proxy_get_filenames will
   * overwrite the pointers, not the data itself.
   */
  ccaf = NULL;
  cd   = NULL;
  inof = of   = (file.empty() ? NULL : const_cast<char *>(file.c_str()));
  cf   = NULL;
  kf   = NULL;
    
  if (!determine_filenames(&ccaf, &cd, &of, &cf, &kf, 0)) {
    std::string output = OpenSSLError(debug);

    std::cerr << output;

    goto err;
  }

  if (of != inof)
    file = std::string(of);

  in = BIO_new(BIO_s_file());
  if (in) {
    if (BIO_read_filename(in, of) > 0) {
      x = PEM_read_bio_X509(in, NULL, 0, NULL);
      if(!x) {
        std::cerr << "Couldn't find a valid proxy." << std::endl;
        goto err;
      }
      chain = load_chain_from_file(of);


      vomsdata d("","");
      if (!dont_verify_ac) {
          d.SetVerificationType((verify_type)(VERIFY_SIGN | VERIFY_KEY));
          res = d.Retrieve(x, chain, RECURSE_CHAIN);
      }
      if (dont_verify_ac || !res || d.error == VERR_NOEXT) {
        d.data.clear();
        d.SetVerificationType((verify_type)(VERIFY_NONE));
        res = d.Retrieve(x, chain, RECURSE_CHAIN);
        if ( dont_verify_ac || d.error == VERR_NOEXT ) {
            res = true;
        }
      }

      if (!res) {
        std::cerr << "WARNING: Unable to verify signature! Server certificate possibly not installed.\n" 
                  << "Error: " << d.ErrorMessage() << std::endl;

      }

      bool print_res = print(x, chain, d);
      if (print_res == false) {
          res = false;
      }
    }
    else {
      std::cerr << std::endl << "Couldn't find a valid proxy." << std::endl << std::endl;
      goto err;
    }
  }

 err:
  BIO_free(in);
  BIO_free(bio_err);

  return res;
}

static STACK_OF(X509) *load_chain_from_file(char *certfile)
{
  BIO *bio = NULL;
  STACK_OF(X509) *stack = NULL;

  bio = BIO_new_file(certfile, "r");

  if (bio) {
    stack = load_chain(bio, certfile);
    BIO_free(bio);
  }
  else {
    printf("error opening the file, %s\n",certfile);
  }

  return stack;
}


static ASN1_TIME *
convtime(std::string data)
{
  ASN1_TIME *t= ASN1_TIME_new();

  t->data   = (unsigned char *)(data.data());
  t->length = data.size();
  switch(t->length) {
  case 10:
    t->type = V_ASN1_UTCTIME;
    break;
  case 15:
    t->type = V_ASN1_GENERALIZEDTIME;
    break;
  default:
    ASN1_TIME_free(t);
    return NULL;
  }
  return t;
}

static bool print(X509 *cert, STACK_OF(X509) *chain, vomsdata &vd)
{
  time_t now;
  time(&now);
  time_t leftcert = stillvalid(X509_get_notAfter(cert)) - now;
  leftcert = (leftcert < 0) ? 0 : leftcert;

  int totbits = numbits(cert);

  bool res = true;

  time_t leftac;

  if (dochain && chain) {
    int start = sk_X509_num(chain);
    X509 *cert = NULL;
    if (start >= 1) {
      std::cout << "=== Proxy Chain Information ===" << std::endl;

      for (start = sk_X509_num(chain)-1; start >= 1; start--) {
        int totbits = 0;
        time_t leftcert = 0;

        cert = sk_X509_value(chain, start);
        totbits = numbits(cert);
        leftcert = stillvalid(X509_get_notAfter(cert)) - now;
        leftcert = (leftcert < 0) ? 0 : leftcert;

        const char *type = proxy_type(cert);

        std::cout << "subject   : " << X509_NAME_oneline(X509_get_subject_name(cert), NULL, 0) << "\n";
        std::cout << "issuer    : " << X509_NAME_oneline(X509_get_issuer_name(cert), NULL, 0) << "\n";
        
        if (strcmp(type, "unknown") != 0)
          std::cout << "type      : " << type << "\n";

	if (all || keyusage)
	  std::cout << "key usage : " << getKeyUsage(cert) << "\n";
        std::cout << "strength  : " << totbits << " bits" << "\n";
        std::cout << "timeleft  : " << leftcert/3600 << ":" << std::setw(2) << std::setfill('0') 
                  << (leftcert%3600)/60 << ":" << std::setw(2) << std::setfill('0') << (leftcert%3600)%60 << "\n\n";
      }
    }
    std::cout << "=== Proxy Information ===\n";
  }
 
  if (defaultinfo || all || text) {
    std::cout << "subject   : " << X509_NAME_oneline(X509_get_subject_name(cert), NULL, 0) << "\n";
    std::cout << "issuer    : " << X509_NAME_oneline(X509_get_issuer_name(cert), NULL, 0) << "\n";
    std::cout << "identity  : " << X509_NAME_oneline(X509_get_issuer_name(cert), NULL, 0) << "\n";
    std::cout << "type      : " << proxy_type(cert) << "\n";
    std::cout << "strength  : " << totbits << " bits" << "\n";
    std::cout << "path      : " << file << "\n";
    std::cout << "timeleft  : " << leftcert/3600 << ":" << std::setw(2) << std::setfill('0') 
              << (leftcert%3600)/60 << ":" << std::setw(2) << std::setfill('0') << (leftcert%3600)%60 << "\n";
    if (!vd.extra_data.empty())
      std::cout << "included  : "  << vd.extra_data << "\n";
    if (all || text || keyusage)
      std::cout << "key usage : " << getKeyUsage(cert) << "\n";
  }    
  
  if (all) {
    for (std::vector<voms>::iterator v = vd.data.begin(); v != vd.data.end(); v++) {
      ASN1_TIME * after  = convtime(v->date2);
      leftac = stillvalid(after) - now;	
      leftac = (leftac<0) ? 0 : leftac;

      std::cout << "=== VO " << v->voname << " extension information ===\n";
      std::cout << "VO        : " << v->voname << "\n";
      std::cout << "subject   : " << v->user << "\n";
      std::cout << "issuer    : " << v->server << "\n";

      for (std::vector<std::string>::iterator s = v->fqan.begin(); s != v->fqan.end(); s++)
        std::cout << "attribute : " << *s << "\n";
      std::vector<attributelist> alist = v->GetAttributes();
      for (std::vector<attributelist>::iterator s = alist.begin(); s != alist.end(); s++)
        for (std::vector<attribute>::iterator t = s->attributes.begin(); t != s->attributes.end(); t++)
          std::cout << "attribute : " << t->name + " = " + t->value + 
            (t->qualifier.empty() ? "" : " (" + t->qualifier + ")") << std::endl;
      std::cout << "timeleft  : " << leftac/3600 << ":" << std::setw(2) << std::setfill('0')
                << (leftac%3600)/60 << ":" << std::setw(2) << std::setfill('0') << (leftac%3600)%60 << "\n";

      std::vector<std::string> targetlist = v->GetTargets();
      if (!targetlist.empty()) {
        for (std::vector<std::string>::iterator targ = targetlist.begin(); targ != targetlist.end(); targ++)
          std::cout << "target    : " << *targ << "\n";
      }
      std::cout << "uri       : " << v->uri  << "\n";

    }
  }

  if (subject)
    std::cout << X509_NAME_oneline(X509_get_subject_name(cert), NULL, 0) << "\n";
  if (issuer)
    std::cout << X509_NAME_oneline(X509_get_issuer_name(cert), NULL, 0) << "\n";
  if (identity)
    std::cout << X509_NAME_oneline(X509_get_issuer_name(cert), NULL, 0) << "\n";
  if (type)
    std::cout << proxy_type(cert) << "\n";
  if (strength)
    std::cout << totbits << "\n";
  if(path)
    std::cout << file << "\n";
  if(timeleft)
    std::cout << leftcert << "\n";
  if (included)
    if (!vd.extra_data.empty())
      std::cout << "included  : "  << vd.extra_data << "\n";


  if(text) {
    X509 *tmp = X509_dup(cert);
    X509_print_fp(stdout, tmp);

    if (dochain) {
      for (int start = sk_X509_num(chain)-1; start >= 1; start--) {
        X509 *tmp = sk_X509_value(chain, start);
        X509 *cert = X509_dup(tmp);
        X509_print_fp(stdout, cert);
      }
    }
  }

  if (vd.data.empty())
    if (vo || acsubject || acissuer || actimeleft || fqan || serial || targets || printuri)
      res = false;

  for (std::vector<voms>::iterator v = vd.data.begin(); v != vd.data.end(); v++) {
    if(vo)
        std::cout << v->voname << "\n";

    if (acsubject) 
        std::cout << v->user << "\n";

    if (acissuer) 
        std::cout << v->server << "\n";

    if (printuri)
      std::cout  << v->uri << "\n";

    ASN1_TIME * after  = convtime(v->date2);
    leftac = stillvalid(after) - now;
    leftac = (leftac<0) ? 0 : leftac;

    if (actimeleft)
        std::cout << leftac << "\n";

    if (fqan) {
      for (std::vector<std::string>::iterator s = v->fqan.begin(); s != v->fqan.end(); s++)
        std::cout << *s << "\n";
      if (v->fqan.empty())
        res = false;
    }

    if (serial)
        std::cout << v->serial << "\n";

    if (targets) {
      std::vector<std::string> targetlist = v->GetTargets();

      if (!targetlist.empty()) {
        for (std::vector<std::string>::iterator targ = targetlist.begin(); targ != targetlist.end(); targ++)
          std::cout << "target    : " << *targ << "\n";
      }
    }
  }

  /* -exists */

  if (exists) {
    if(leftcert==0)
      res = false;
    if(leftcert < (hours*3600 + minutes*60))
      res = false;
    if(totbits < bits)
      res = false;
  }
  
  /* -acexists */

  if(res) {
    for (std::vector<std::string>::iterator i = acexists.begin(); i != acexists.end(); ++i) {
      bool found = false;

      if(res) {
        for (std::vector<voms>::iterator v = vd.data.begin(); v != vd.data.end(); ++v) {
          if(v->voname == *i) {
            found = true;
            break;
          }
        }
      }
      if (!found)
        res = false;
    }
  }
  
  return res;
}    


static time_t stillvalid(ASN1_TIME *ctm)
{
  return ASN1_TIME_mktime(ctm);
}

static std::string getKeyUsage(X509 *cert)
{
  STACK_OF(CONF_VALUE) *confs = NULL;
  ASN1_BIT_STRING *usage = NULL;

  std::string keyusage;

  confs = NULL;
  usage = (ASN1_BIT_STRING*)X509_get_ext_d2i(cert, NID_key_usage, NULL, NULL);
  confs = v3_key_usage.i2v((X509V3_EXT_METHOD*)&v3_key_usage, usage, confs);
  for (int i =0; i < sk_CONF_VALUE_num(confs); i ++) {
    CONF_VALUE *conf = (CONF_VALUE*)sk_CONF_VALUE_value(confs, i);
    keyusage += std::string(conf->name);
    if (i != (sk_CONF_VALUE_num(confs) -1))
      keyusage += ", ";
  }

  ASN1_BIT_STRING_free(usage);

  // Do not free it.  CONF_VALUE_free() is not defined.  The program
  //  ends, so the loss of memory is irrelevant.
  //  sk_CONF_VALUE_pop_free(confs, CONF_VALUE_free);

  return keyusage;
}
