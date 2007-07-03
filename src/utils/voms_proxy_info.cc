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
/*
 * No original header was present, but the still_valid() function was
 * adapted from original Globus code.
 */

/**********************************************************************
                             Include header files
**********************************************************************/
#include "config.h"
#include "replace.h"

//const std::string VERSION         = "0.1";

extern "C" {
#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
  //#include <getopt.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

#include "gssapi.h"

#include "openssl/buffer.h"
#include "openssl/crypto.h"
#include "openssl/objects.h"
#include "openssl/asn1.h"
#include "openssl/evp.h"
#include "openssl/x509.h"
#include "openssl/pem.h"
#include "openssl/ssl.h"
#include "openssl/rsa.h"

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
static STACK_OF(X509) *load_chain(char *certfile);
static time_t stillvalid(ASN1_TIME *ctm);
static char *proxy_type(X509 *cert);

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

static int InitProxyCertInfoExtension(void);
static void *myproxycertinfo_s2i(struct v3_ext_method *method, struct v3_ext_ctx *ctx, char *data);
static char *myproxycertinfo_i2s(struct v3_ext_method *method, void *ext);
static char *norep();

int
main(int argc, char **argv)
{

  (void)InitProxyCertInfoExtension();

  if (strrchr(argv[0],'/'))
    program = strrchr(argv[0],'/') + 1;
  else
    program = argv[0];

  static char *LONG_USAGE = 
    "\n\n"
    "Syntax: voms-proxy-info [-help][-file proxyfile][-subject][...][-exists [-hours H][-bits B]]\n\n"
    "   Options\n"
    "   -help, -usage             Displays usage\n"
    "   -version                  Displays version\n"
    "   -debug                    Displays debugging output\n"
    "   -file <proxyfile>         Non-standard location of proxy\n"
    "   [printoptions]            Prints information about proxy and attribute certificate\n"
    "   -exists [options]         Returns 0 if valid proxy exists, 1 otherwise\n"
    "   -acexists <voname>        Returns 0 if AC exists corresponding to voname, 1 otherwise\n"
    "   -conf <name>              Read options from file <name>\n"
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
    {0, 0, 0, 0}
  };

  if (!getopts(argc, argv, opts))
    exit(1);

  if (progversion) {
    std::cout << SUBPACKAGE << "\nVersion: " << VERSION << std::endl;
    std::cout << "Compiled: " << __DATE__ << " " << __TIME__ << std::endl;
    exit(0);
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


static char *proxy_type(X509 *cert)
{
  char *buffer = X509_NAME_oneline(X509_get_subject_name(cert), NULL, 0);
  char *point1 = strstr(buffer,"CN=proxy");
  char *point2 = strstr(buffer,"CN=limited proxy");
  int len = strlen(buffer);

  OPENSSL_free(buffer);

  if (point1)
    if (len == ((point1 - buffer) + 8))
      return "proxy";

  if (point2)
    if (len == ((point2 - buffer) + 16))
      return "limited proxy";

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
  of   = (file.empty() ? NULL : const_cast<char *>(file.c_str()));
  cf   = NULL;
  kf   = NULL;
    
  if (proxy_get_filenames(pcd,0, &ccaf, &cd, &of, &cf, &kf))
    goto err;

  file = std::string(of);

  in = BIO_new(BIO_s_file());
  if (in) {
    if (BIO_read_filename(in, of) > 0) {
      x = PEM_read_bio_X509(in, NULL, 0, NULL);
      if(!x) {
        std::cerr << "Couldn't find a valid proxy." << std::endl;
        goto err;
      }
      chain = load_chain(of);
      vomsdata d("","");
      d.SetVerificationType((verify_type)(VERIFY_SIGN | VERIFY_KEY));
      res = d.Retrieve(x, chain, RECURSE_CHAIN);
      if (!res) {
        d.data.clear();
        d.SetVerificationType((verify_type)(VERIFY_NONE));
        res = d.Retrieve(x, chain, RECURSE_CHAIN);
        std::cerr << "WARNING: Unable to verify signature! Server certificate possibly not installed.\n" 
                  << "Error: " << d.ErrorMessage() << std::endl;
      }
      res &= !(print(x, chain, d));
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

static STACK_OF(X509) *load_chain(char *certfile)
{
  STACK_OF(X509_INFO) *sk=NULL;
  STACK_OF(X509) *stack=NULL, *ret=NULL;
  BIO *in=NULL;
  X509_INFO *xi;
  int first = 1;

  if(!(stack = sk_X509_new_null())) {
    printf("memory allocation failure\n");
    goto end;
  }

  if(!(in=BIO_new_file(certfile, "r"))) {
    printf("error opening the file, %s\n",certfile);
    goto end;
  }

  /* This loads from a file, a stack of x509/crl/pkey sets */
  if(!(sk=PEM_X509_INFO_read_bio(in,NULL,NULL,NULL))) {
    printf("error reading the file, %s\n",certfile);
    goto end;
  }

  /* scan over it and pull out the certs */
  while (sk_X509_INFO_num(sk)) {
    /* skip first cert */
    if (first) {
      first = 0;
      continue;
    }
    xi=sk_X509_INFO_shift(sk);
    if (xi->x509 != NULL) {
      sk_X509_push(stack,xi->x509);
      xi->x509=NULL;
    }
    X509_INFO_free(xi);
  }
  if(!sk_X509_num(stack)) {
    printf("no certificates in file, %s\n",certfile);
    sk_X509_free(stack);
    goto end;
  }
  ret=stack;
end:
  BIO_free(in);
  sk_X509_INFO_free(sk);
  return(ret);
}

// static std::string 
// timestring(ASN1_TIME *time)
// {
//   std::string res = "";

//   if (time) {
//     BIO *bio= BIO_new(BIO_s_mem());
//     if (bio) {
//       if (ASN1_TIME_print(bio,time)) {
//         int len;
//         char *s;
//         len = BIO_get_mem_data(bio, &s);
//         res = std::string(s,len);
//       }
//       BIO_free(bio);
//     }
//   }
//   return res;
// }

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
        char *type = NULL;
        int totbits = 0;
        time_t leftcert = 0;

        cert = sk_X509_value(chain, start);
        totbits = numbits(cert);
        leftcert = stillvalid(X509_get_notAfter(cert)) - now;
        leftcert = (leftcert < 0) ? 0 : leftcert;
        type = proxy_type(cert);

        std::cout << "subject   : " << X509_NAME_oneline(X509_get_subject_name(cert), NULL, 0) << "\n";
        std::cout << "issuer    : " << X509_NAME_oneline(X509_get_issuer_name(cert), NULL, 0) << "\n";
        
        if (strcmp(type, "unknown") != 0)
          std::cout << "type      : " << proxy_type(cert) << "\n";
        
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

  if(text) {
    X509 *tmp = (X509 *)ASN1_dup((int (*)())i2d_X509,
				   (char * (*)())d2i_X509, (char*)cert);
    X509_print_fp(stdout, tmp);

    if (dochain) {
      for (int start = sk_X509_num(chain)-1; start >= 1; start--) {
	X509 *tmp = sk_X509_value(chain, start);
	X509 *cert = (X509 *)ASN1_dup((int (*)())i2d_X509,
				      (char * (*)())d2i_X509, (char*)tmp);
	X509_print_fp(stdout, cert);
      }
    }
  }

  if (vd.data.empty())
    if (vo || acsubject || acissuer || actimeleft || fqan || serial)
      res = false;

  for (std::vector<voms>::iterator v = vd.data.begin(); v != vd.data.end(); v++) {
    if(vo)
        std::cout << v->voname << "\n";

    if (acsubject) 
        std::cout << v->user << "\n";

    if (acissuer) 
        std::cout << v->server << "\n";

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

  if(!res) {
    for (std::vector<std::string>::iterator i = acexists.begin(); i != acexists.end(); ++i) {
      bool found = false;

      if(!res) {
        for (std::vector<voms>::iterator v = vd.data.begin(); v != vd.data.end(); ++v) {
          if(v->voname == *i) {
            found = true;
            break;
          }
        }
      }
      if (!found)
        res = false;
      found = true;
    }
  }
  
  return res;
}    


static time_t stillvalid(ASN1_TIME *ctm)
{
  char     *str;
  time_t    offset;
  time_t    newtime;
  char      buff1[32];
  char     *p;
  int       i;
  struct tm tm;
  int       size;

  switch (ctm->type) {
  case V_ASN1_UTCTIME:
    size=10;
    break;
  case V_ASN1_GENERALIZEDTIME:
    size=12;
    break;
  }
  p = buff1;
  i = ctm->length;
  str = (char *)ctm->data;
  if ((i < 11) || (i > 17)) {
    newtime = 0;
  }
  memcpy(p,str,size);
  p += size;
  str += size;

  if ((*str == 'Z') || (*str == '-') || (*str == '+')) {
    *(p++)='0'; *(p++)='0';
  }
  else {
    *(p++)= *(str++); *(p++)= *(str++);
  }
  *(p++)='Z';
  *(p++)='\0';

  if (*str == 'Z') {
    offset=0;
  }
  else {
    if ((*str != '+') && (str[5] != '-')) {
      newtime = 0;
    }
    offset=((str[1]-'0')*10+(str[2]-'0'))*60;
    offset+=(str[3]-'0')*10+(str[4]-'0');
    if (*str == '-') {
      offset=-offset;
    }
  }

  tm.tm_isdst = 0;
  int index = 0;
  if (ctm->type == V_ASN1_UTCTIME) {
    tm.tm_year  = (buff1[index++]-'0')*10;
    tm.tm_year += (buff1[index++]-'0');
  }
  else {
    tm.tm_year  = (buff1[index++]-'0')*1000;
    tm.tm_year += (buff1[index++]-'0')*100;
    tm.tm_year += (buff1[index++]-'0')*10;
    tm.tm_year += (buff1[index++]-'0');
  }

  if (tm.tm_year < 70) {
    tm.tm_year+=100;
  }

  if (tm.tm_year > 1900) {
    tm.tm_year -= 1900;
  }

  tm.tm_mon   = (buff1[index++]-'0')*10;
  tm.tm_mon  += (buff1[index++]-'0')-1;
  tm.tm_mday  = (buff1[index++]-'0')*10;
  tm.tm_mday += (buff1[index++]-'0');
  tm.tm_hour  = (buff1[index++]-'0')*10;
  tm.tm_hour += (buff1[index++]-'0');
  tm.tm_min   = (buff1[index++]-'0')*10;
  tm.tm_min  += (buff1[index++]-'0');
  tm.tm_sec   = (buff1[index++]-'0')*10;
  tm.tm_sec  += (buff1[index++]-'0');

  /*
   * mktime assumes local time, so subtract off
   * timezone, which is seconds off of GMT. first
   * we need to initialize it with tzset() however.
   */

  tzset();

#if defined(HAVE_TIME_T_TIMEZONE)
  newtime = (mktime(&tm) + offset*60*60 - timezone);
#elif defined(HAVE_TIME_T__TIMEZONE)
  newtime = (mktime(&tm) + offset*60*60 - _timezone);
#else
  newtime = (mktime(&tm) + offset*60*60);
#endif

  return newtime;
}

static int InitProxyCertInfoExtension(void)
{

#define PROXYCERTINFO_V3      "1.3.6.1.4.1.3536.1.222"
#define PROXYCERTINFO_V4      "1.3.6.1.5.5.7.1.14"
#define OBJC(c,n) OBJ_create(c,n,#c)
#define IMPERSONATION_PROXY_OID         "1.3.6.1.5.5.7.21.1"
#define INDEPENDENT_PROXY_OID           "1.3.6.1.5.5.7.21.2"
#define GLOBUS_GSI_PROXY_GENERIC_POLICY_OID "1.3.6.1.4.1.3536.1.1.1.8"
#define LIMITED_PROXY_OID               "1.3.6.1.4.1.3536.1.1.1.9"

  X509V3_EXT_METHOD *pcert;

  /* Proxy Certificate Extension's related objects */
//   OBJC(myPROXYCERTINFO_V3, "myPROXYCERTINFO_V3");
//   OBJC(myPROXYCERTINFO_V4, "myPROXYCERTINFO_V4");
//   OBJC(IMPERSONATION_PROXY_OID, "IMPERSONATION_PROXY_OID");
//   OBJC(INDEPENDENT_PROXY_OID, "INDEPENDENT PROXY_OID");
//   OBJC(GLOBUS_GSI_PROXY_GENERIC_POLICY_OID, "GLOBUS_GSI_PROXY_GENERIC_POLICY_OID");
//   OBJC(LIMITED_PROXY_OID, "LIMITED_PROXY_OID");

  pcert = (X509V3_EXT_METHOD *)OPENSSL_malloc(sizeof(X509V3_EXT_METHOD));

  if (pcert) {
    memset(pcert, 0, sizeof(*pcert));
    pcert->ext_nid = OBJ_txt2nid("PROXYCERTINFO_V3");
    pcert->ext_flags = 0;
    pcert->ext_new  = (X509V3_EXT_NEW) myPROXYCERTINFO_new;
    pcert->ext_free = (X509V3_EXT_FREE)myPROXYCERTINFO_free;
    pcert->d2i      = (X509V3_EXT_D2I) d2i_myPROXYCERTINFO;
    pcert->i2d      = (X509V3_EXT_I2D) i2d_myPROXYCERTINFO;
    pcert->i2s      = (X509V3_EXT_I2S) myproxycertinfo_i2s;
    pcert->s2i      = (X509V3_EXT_S2I) myproxycertinfo_s2i;
    pcert->v2i      = (X509V3_EXT_V2I) NULL;
    pcert->r2i      = (X509V3_EXT_R2I) NULL;
    pcert->i2v      = (X509V3_EXT_I2V) NULL;
    pcert->i2r      = (X509V3_EXT_I2R) NULL;

    X509V3_EXT_add(pcert);
  }

  pcert = (X509V3_EXT_METHOD *)OPENSSL_malloc(sizeof(X509V3_EXT_METHOD));

  if (pcert) {
    memset(pcert, 0, sizeof(*pcert));
    pcert->ext_nid = OBJ_txt2nid("PROXYCERTINFO_V4");
    pcert->ext_flags = 0;
    pcert->ext_new  = (X509V3_EXT_NEW) myPROXYCERTINFO_new;
    pcert->ext_free = (X509V3_EXT_FREE)myPROXYCERTINFO_free;
    pcert->d2i      = (X509V3_EXT_D2I) d2i_myPROXYCERTINFO;
    pcert->i2d      = (X509V3_EXT_I2D) i2d_myPROXYCERTINFO;
    pcert->i2s      = (X509V3_EXT_I2S) myproxycertinfo_i2s;
    pcert->s2i      = (X509V3_EXT_S2I) myproxycertinfo_s2i;
    pcert->v2i      = (X509V3_EXT_V2I) NULL;
    pcert->r2i      = (X509V3_EXT_R2I) NULL;
    pcert->i2v      = (X509V3_EXT_I2V) NULL;
    pcert->i2r      = (X509V3_EXT_I2R) NULL;

    X509V3_EXT_add(pcert);
  }
}

static void *myproxycertinfo_s2i(struct v3_ext_method *method, struct v3_ext_ctx *ctx, char *data)
{
  return (myPROXYCERTINFO*)data;
}

static char *myproxycertinfo_i2s(struct v3_ext_method *method, void *ext)
{
  return norep();
}

static char *norep()
{
  static char *buffer = (char *) malloc(1);
  if (buffer)
    buffer='\0';
  return buffer;
}
