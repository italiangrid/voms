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

extern "C" {
#ifdef NOGLOBUS
#include <pthread.h>
#endif

#include "config.h"
#include "replace.h"

#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#ifdef HAVE_GETPWNAM
#include <pwd.h>
#endif
#include <stdlib.h>
#include <dirent.h>
#include "newformat.h"
#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include "credentials.h"

#ifndef NOGLOBUS
#ifdef HAVE_GLOBUS_MODULE_ACTIVATE
#include <globus_module.h>
#include <globus_openssl.h>
#endif
#else
#include <openssl/crypto.h>
#endif
}

#include <fstream>
#include <iostream>

#include <voms_api.h>
#include "data.h"
#include "vomsxml.h"

#include "realdata.h"

extern bool retrieve(X509 *cert, STACK_OF(X509) *chain, recurse_type how, 
		     std::string &buffer, std::string &vo, std::string &file, 
		     std::string &subject, std::string &ca, verror_type &error);
/*
extern bool verify(std::string message, vomsdata &voms, verror_type &error, 
		   std::string vdir, std::string cdir, std::string subject, 
		   std::string ca);
*/

extern "C" {
extern char *Decode(const char *, int, int *);
extern char *Encode(const char *, int, int *, int);
}

extern int AC_Init(void);

#ifdef NOGLOBUS
static pthread_mutex_t *mut_pool = NULL;

static void locking_cb(int mode, int type, const char *file, int line)
{
  if (pthread_mutex_lock)
    if (mode & CRYPTO_LOCK)
      pthread_mutex_lock(&(mut_pool[type]));
    else
      pthread_mutex_unlock(&(mut_pool[type]));
}


/**
 * OpenSSL thread id callback
 *
 */
static unsigned long thread_id(void)
{
  if (pthread_self)
    return (unsigned long) pthread_self();
  else
    return 0;
}

static void openssl_initialize(void)
{
  mut_pool = (pthread_mutex_t *)malloc(CRYPTO_num_locks() * sizeof(pthread_mutex_t));

  fprintf(stderr, "It appears that the value of pthread_mutex_init is %d\n",
          pthread_mutex_init);
  if (pthread_mutex_init)
    for(int i = 0; i < CRYPTO_num_locks(); i++)
      pthread_mutex_init(&(mut_pool[i]),NULL);

  CRYPTO_set_locking_callback(locking_cb);
  CRYPTO_set_id_callback(thread_id);

  OBJ_create("0.9.2342.19200300.100.1.1","USERID","userId");

#if 0
  OBJ_create("1.3.6.1.5.5.7.21.1", "IMPERSONATION_PROXY",
             "GSI Impersonation Proxy");

  OBJ_create("1.3.6.1.5.5.7.21.2", "INDEPENDENT_PROXY",
             "GSI Independent Proxy");

  OBJ_create("1.3.6.1.4.1.3536.1.1.1.9", "LIMITED_PROXY",
             "GSI Limited Proxy");
    
  int pci_NID = OBJ_create("1.3.6.1.4.1.3536.1.222", "PROXYCERTINFO",
                           "Proxy Certificate Info Extension");

  X509V3_EXT_METHOD *pci_x509v3_ext_meth = PROXYCERTINFO_x509v3_ext_meth();

  /* this sets the pci NID in the static X509V3_EXT_METHOD struct */
  pci_x509v3_ext_meth->ext_nid = pci_NID;
    
  X509V3_EXT_add(pci_x509v3_ext_meth);
#endif
}

#else
/* ndef NOGLOBUS */

static globus_thread_once_t l_globus_once_control = GLOBUS_THREAD_ONCE_INIT;

static void l_init_globus_once_func(void) {
#ifdef HAVE_GLOBUS_MODULE_ACTIVATE
    (void)globus_module_activate(GLOBUS_GSI_GSS_ASSIST_MODULE);
    (void)globus_module_activate(GLOBUS_OPENSSL_MODULE);
#endif
    SSLeay_add_all_algorithms();
    ERR_load_crypto_strings();
    (void)AC_Init();
}

#endif

vomsdata::Initializer::Initializer(Initializer &) {}
vomsdata::Initializer::Initializer()
{
#ifdef NOGLOBUS
  openssl_initialize();
  SSLeay_add_all_algorithms();
  ERR_load_crypto_strings();

  (void)AC_Init();
#endif
}

vomsdata::Initializer vomsdata::init;
//bool vomsdata::initialized = false;

void vomsdata::seterror(verror_type err, std::string message)
{
  error = err;
  errmessage = message;
}

std::string vomsdata::ErrorMessage(void)
{
  return errmessage;
}

vomsdata::vomsdata(std::string voms_dir, std::string cert_dir) :  ca_cert_dir(cert_dir),
                                                                  voms_cert_dir(voms_dir),
                                                                  duration(0),
                                                                  ordering(""),
                                                                  error(VERR_NONE),
                                                                  workvo(""),
                                                                  extra_data(""),
                                                                  ver_type(VERIFY_FULL),
                                                                  retry_count(1)
{
#ifndef NOGLOBUS
   (void)globus_thread_once(&l_globus_once_control, l_init_globus_once_func);
#endif

  if (voms_cert_dir.empty()) {
    char *v;
    if ( (v = getenv("X509_VOMS_DIR")))
      voms_cert_dir = std::string(v);
    else 
      voms_cert_dir = "/etc/grid-security/vomsdir";
  }

  if (ca_cert_dir.empty()) {
    char *c;
    if ((c = getenv("X509_CERT_DIR")))
      ca_cert_dir = std::string(c);
    else
      ca_cert_dir = "/etc/grid-security/certificates";
  }

  DIR *vdir, *cdir;
  vdir = opendir(voms_cert_dir.c_str());
  cdir = opendir(ca_cert_dir.c_str());

  if (!vdir)
    seterror(VERR_DIR, "Unable to find vomsdir directory");

  if (!cdir)
    seterror(VERR_DIR, "Unable to find ca certificates");

  if (cdir)
    (void)closedir(cdir);
  if (vdir)
    (void)closedir(vdir);

  duration = 0;
}

vomsdata::~vomsdata()
{
#ifndef NOGLOBUS
  //#ifdef HAVE_GLOBUS_MODULE_ACTIVATE
#if 0
  if (!noglobus) {
    globus_module_deactivate(GLOBUS_GSI_GSS_ASSIST_MODULE);
    globus_module_deactivate(GLOBUS_OPENSSL_MODULE);
  }
#endif
#endif
}

std::string vomsdata::ServerErrors(void)
{
  std::string err = serverrors;
  serverrors="";

  return err;
}

void vomsdata::ResetTargets(void)
{
  targets.clear();
}

std::vector<std::string> vomsdata::ListTargets(void)
{
  return targets;
}

void vomsdata::AddTarget(std::string target)
{
  targets.push_back(target);
}

void vomsdata::SetLifetime(int lifetime)
{
  duration = lifetime;
}

void vomsdata::SetVerificationType(verify_type t)
{
  ver_type = t;
}

void vomsdata::ResetOrder(void)
{
  ordering="";
}

void vomsdata::Order(std::string att)
{
  /*
  std::string::size_type position = att.find("/Role=");
  if (position == std::string::npos)
  */  
  ordering += (ordering.empty() ? ""  : ",") + att;
  /*
  else {
    std::string temp = att.substr(0, position) + ":" + att.substr(position+6);
    ordering += (ordering.empty() ? ""  : ",") + temp;
  }
  */
}

bool vomsdata::ContactRaw(std::string hostname, int port, std::string servsubject, std::string command, std::string &raw, int& version)
{
#ifndef NOGLOBUS
  std::string buffer;
  std::string subject, ca;
  std::string lifetime;

  std::string comm;
  std::string targs;
  answer a;

  for (std::vector<std::string>::iterator i = targets.begin(); 
       i != targets.end(); i++) {
    if (i == targets.begin())
      targs = *i;
    else
      targs += std::string(",") + *i;
  }

  comm = XML_Req_Encode(command, ordering, targs, duration);

  if (!contact(hostname, port, servsubject, comm, buffer, subject, ca))
    return false;
  
  if (XML_Ans_Decode(buffer, a)) {
    bool result = true;
    if (!a.ac.empty()) {
      buffer = a.ac;
      if (a.errs.size() != 0) {
        for (std::vector<errorp>::iterator i = a.errs.begin();
             i != a.errs.end(); i++) {
          serverrors += i->message;
          if (i->num > ERROR_OFFSET)
            result = false;
          if (i->num == WARN_NO_FIRST_SELECT)
            seterror(VERR_ORDER, "Cannot put requested attributes in the specified order.");
        }
      }
    }
    else if (!a.data.empty()) {
      buffer = a.data;
    }
    if (!result && ver_type) {
      seterror(VERR_SERVERCODE, "The server returned an error.");
      return false;
    }
    raw = buffer;
  }
  else {
    seterror(VERR_FORMAT, "Server Answer was incorrectly formatted.");
    return false;
  }

  version = 1;
  return true;
#else
  seterror(VERR_NOTAVAIL, "Method not available in this library!");
  return false;
#endif
}

bool vomsdata::Contact(std::string hostname, int port, std::string servsubject, std::string command)
{
#ifndef NOGLOBUS
  std::string subject, ca;
  char *s = NULL, *c = NULL;

  std::string message;
  bool result = false;
  int version;

  for (int i=0; i < retry_count; ++i)
  {
    if (ContactRaw(hostname, port, servsubject, command, message, version)) {

      X509 *holder = get_own_cert();

      if (holder) {
        error = VERR_NONE;
        c = X509_NAME_oneline(X509_get_issuer_name(holder), NULL,  0);
        s = X509_NAME_oneline(X509_get_subject_name(holder), NULL, 0);
      
        if (c && s) {
          ca = std::string(c);
          subject = std::string(s);
    
          voms v;
          
          result = verifydata(message, subject, ca, holder, v);
	
          if (result)
            data.push_back(v);
        }
        X509_free(holder);
      }
      else
        seterror(VERR_NOIDENT, "Cannot discover own credentials.");
      
      break;
    }
  }
  
  free(c);
  free(s);

  return result;
#else
  seterror(VERR_NOTAVAIL, "Method not available in this library!");
  return false;
#endif
}

STACK_OF(X509) *vomsdata::load_chain(BIO *in)
{
  STACK_OF(X509_INFO) *sk=NULL;
  STACK_OF(X509) *stack=NULL, *ret=NULL;
  X509_INFO *xi;
  int first = 1;

  stack = sk_X509_new_null();
  if (!stack)
    return NULL;

  /* This loads from a file, a stack of x509/crl/pkey sets */
  if(!(sk=PEM_X509_INFO_read_bio(in,NULL,NULL,NULL))) {
    seterror(VERR_PARSE, "error reading credentials from file.");
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
    seterror(VERR_PARSE, "no certificates in file.");
    sk_X509_free(stack);
    goto end;
  }
  ret=stack;
end:
  sk_X509_INFO_pop_free(sk, X509_INFO_free);
  return(ret);
}

bool vomsdata::Retrieve(FILE *file, recurse_type how)
{
  /* read and builds chain */

  BIO *in = NULL;
  X509 *x = NULL;
  bool res = false;

  in = BIO_new_fp(file, BIO_NOCLOSE);
  if (in) {
      x = PEM_read_bio_X509(in, NULL, 0, NULL);
      STACK_OF(X509) *chain = load_chain(in);
      if (x && chain)
        res = Retrieve(x, chain, how);
      X509_free(x);
      sk_X509_pop_free(chain, X509_free);
  }
  BIO_free(in);
  return res;
}

bool vomsdata::RetrieveFromCred(gss_cred_id_t cred, recurse_type how)
{
#ifndef NOGLOBUS
  X509 *cert;
  STACK_OF(X509) *chain;

  cert = decouple_cred(cred, 0, &chain);

  return Retrieve(cert, chain, how);
#else
  seterror(VERR_NOTAVAIL, "Method not available in this library!");
  return false;
#endif
}

bool vomsdata::RetrieveFromCtx(gss_ctx_id_t cred, recurse_type how)
{
#ifndef NOGLOBUS
  X509 *cert;
  STACK_OF(X509) *chain;

  cert = decouple_ctx(cred, 0, &chain);

  return Retrieve(cert, chain, how);
#else
  seterror(VERR_NOTAVAIL, "Method not available in this library!");
  return false;
#endif
}

bool vomsdata::RetrieveFromProxy(recurse_type how)
{
#ifndef NOGLOBUS
  gss_cred_id_t cred = GSS_C_NO_CREDENTIAL;

  OM_uint32 major, minor, status;

  major = minor = status = 0;

  major = globus_gss_assist_acquire_cred(&minor, GSS_C_BOTH, &cred);
  if (major != GSS_S_COMPLETE) {
    seterror(VERR_NOIDENT, "Could not load proxy.");
  }
  
  bool b = RetrieveFromCred(cred, how);
  gss_release_cred(&status, &cred);
  return b;
#else
  seterror(VERR_NOTAVAIL, "Method not available in this library!");
  return false;
#endif
}

bool vomsdata::Retrieve(X509_EXTENSION *ext)
{
  verify_type v = ver_type;
  ver_type = (verify_type)((int)ver_type & (~VERIFY_ID));

  bool ret = evaluate((AC_SEQ*)X509V3_EXT_d2i(ext), "", "", NULL);

  ver_type = v;

  return ret;
}

bool vomsdata::Retrieve(X509 *cert, STACK_OF(X509) *chain, recurse_type how)
{
  bool ok = false;

  std::string subject;
  std::string ca;
  AC_SEQ *acs = NULL;
  X509 *holder = NULL;

  if (retrieve(cert, chain, how, &acs, subject, ca, &holder)) {
    ok = evaluate(acs, subject, ca, holder);
  }

  if (acs)
    AC_SEQ_free(acs);
  if (holder)
    X509_free(holder);

  return ok;
}

bool vomsdata::Import(std::string buffer)
{
  bool result = false;

  X509 *holder;
  char *buf = NULL;

  std::string subject, ca;
#if OPENSSL_VERSION_NUMBER >= 0x00908000L
  const unsigned char *buftmp, *copy;
#else
  unsigned char *buftmp, *copy;
#endif

  char *str;
  int len;

  str = Decode(buffer.c_str(), buffer.size(), &len);
  if (str) {
    buffer = std::string(str, len);
    free(str);
  }
  else {
    seterror(VERR_FORMAT, "Malformed input data.");
    return false;
  }

  do {
    copy = buftmp = (unsigned char *)(const_cast<char *>(buffer.data()));

    holder = d2i_X509(NULL, &copy, buffer.size());

    if (holder) {
      buf = X509_NAME_oneline(X509_get_subject_name(holder), NULL, 0);
      if (buf) 
        subject = std::string(buf);
      OPENSSL_free(buf);
      buf = X509_NAME_oneline(X509_get_issuer_name(holder), NULL, 0);
      if (buf)
        ca = std::string(buf);
      OPENSSL_free(buf);

      voms v;

      buffer = buffer.substr(copy - buftmp);
      result = verifydata(buffer, subject, ca, holder, v);
      if (result)
        data.push_back(v);
      X509_free(holder);
    }
    else {
      seterror(VERR_NOIDENT, "Cannot discovere AC issuer.");
      return false;
    }
  } while (!buffer.empty() &&  result);

  return result;
}

bool vomsdata::Export(std::string &buffer)
{
  std::string result;
  std::string temp;

  if (data.empty()) {
    buffer= "";
    return true;
  }

  for (std::vector<voms>::iterator v=data.begin(); v != data.end(); v++) {
    /* Dump owner's certificate */
    int l;
    unsigned char *xtmp, *xtmp2;

    l = i2d_X509(v->holder, NULL);
    if (!l) {
      seterror(VERR_FORMAT, "Malformed input data.");
      return false;
    }
    if ((xtmp2 = (xtmp = (unsigned char *)OPENSSL_malloc(l)))) {
      i2d_X509(v->holder, &xtmp);
      result += std::string((char *)xtmp2, l);
      OPENSSL_free(xtmp2);
    }
    else {
      seterror(VERR_MEM, "Out of memory!");
      return false;
    }

    /* This is an AC format. */
    int len  = i2d_AC(((struct realdata *)v->realdata)->ac, NULL);
    unsigned char *tmp, *tmp2;

    if ((tmp2 = (tmp = (unsigned char *)OPENSSL_malloc(len)))) {
      i2d_AC(((struct realdata *)v->realdata)->ac,&tmp);
      result += std::string((char *)tmp2, len);
      OPENSSL_free(tmp2);
    }
    else {
      seterror(VERR_MEM, "Out of memory!");
      return false;
    }
  }

  char *str;
  int len;
  str = Encode(result.c_str(), result.size(), &len, 0);
  if (str) {
    buffer = std::string(str, len);
    free(str);
    return true;
  }
  else
    return false;
}

bool vomsdata::DefaultData(voms &d)
{
  if (data.empty()) {
    seterror(VERR_NOEXT, "No VOMS extensions have been processed.");
    return false;
  }

  d = data.front();
  return true;
}

bool vomsdata::loadfile(std::string filename, uid_t uid, gid_t gid)
{
  struct stat stats;

  struct vomsdata data;

  std::string temp;

  if (filename.empty()) {
    seterror(VERR_DIR, "Filename for vomses file or dir (system or user) unspecified!");
    return false;
  }

  if (stat(filename.c_str(), &stats) == -1) {
    seterror(VERR_DIR, "Cannot find file or dir: " + filename);
    return false;
  }

  if (stats.st_mode & (S_IWGRP | S_IWOTH)) {
    seterror(VERR_DIR, std::string("Wrong permissions on file: ") + filename + 
             "\nWriting permissions are allowed only for the owner\n");
    return false;
  }

  if (stats.st_mode & S_IFREG)
    return loadfile0(filename, 0, 0);
  else {
    DIR *dp = opendir(filename.c_str());
    struct dirent *de;

    if (dp) {
      bool cumulative = false;
      while ((de = readdir(dp))) {
        char *name = de->d_name;
        if (name && (strcmp(name, ".") != 0) && (strcmp(name, "..") != 0))
          cumulative |= loadfile(filename + "/" + name, 0, 0);
      }
      closedir(dp);
      return cumulative;
    }
  }
  return false;
}

static bool
tokenize(std::string str, std::string::size_type &start, std::string &value)
{
  if (start != std::string::npos) {
    std::string::size_type begin = str.find('"',start);
    if (begin != std::string::npos) {
      std::string::size_type end = str.find('"',begin+1);
      if (end != std::string::npos) {
        value = str.substr(begin+1, end-begin-1);
        start = end+1;
        if (start >= str.size())
          start = std::string::npos;
        return true;
      }
    }
  }
  return false;
}

static bool empty(std::string c)
{
  if (c[0] == '#')
    return true;

  for (unsigned int i = 0; i < c.size(); i++)
    if (!isspace(c[i]))
      return false;
  return true;
}

bool vomsdata::loadfile0(std::string filename, uid_t uid, gid_t gid)
{
  struct contactdata data;

  if (filename.empty()) {
    seterror(VERR_DIR, "Filename unspecified.");
    return false;
  }

  /* Opens the file */
  std::ifstream f(filename.c_str());

  if (!f) {
    seterror(VERR_DIR, "Cannot open file: " + filename);
    return false;
  }

  /* Load the file */
  int linenum = 1;
  bool ok = true;
  bool verok = true;

  while (ok && f) {
    std::string line;

    if (getline(f,line) && !empty(line)) {
      ok = verok = true;
      std::string::size_type start = 0;
      std::string port, version;

      ok &= tokenize(line, start, data.nick);
      ok &= tokenize(line, start, data.host);
      ok &= tokenize(line, start, port);
      ok &= tokenize(line, start, data.contact);
      ok &= tokenize(line, start, data.vo);
      verok &= tokenize(line, start, version);

      if (ok) {
        data.port = atoi(port.c_str());
        if (verok)
          data.version = atoi(version.c_str());
        else
          data.version = -1;
        servers.push_back(data);
      }
      else {
        seterror(VERR_FORMAT, "data format in file: " + filename + " incorrect!\nLine: " + line);
        return false;
      }
    }
    linenum++;
  }
  return true;
}

bool vomsdata::LoadSystemContacts(std::string dir)
{
  if (dir.empty())
    dir = "/opt/glite/etc/vomses";

  return loadfile(dir, 0, 0);
}

bool vomsdata::LoadUserContacts(std::string dir)
{
  if (dir.empty()) {
    char *name = getenv("VOMS_USERCONF");
    if (name)
      dir = std::string(name);
    else {
      char *home = getenv("HOME");
      if (home)
        dir = std::string(home) + "/.glite/vomses";
      else {
#ifdef HAVE_GETPWNAM
        struct passwd *pw = getpwuid(getuid());
        if (pw) {
          dir = std::string(pw->pw_dir) + "/.glite/vomses";
        }
        else {
#endif
          return false;
#ifdef HAVE_GETPWNAM
        }
#endif
      }
    }
  }

  return loadfile(dir, 0, 0);
}

std::vector<contactdata>
vomsdata::FindByAlias(std::string nick)
{
  std::vector<contactdata>::iterator beg = servers.begin(), end = servers.end();
  std::vector<contactdata> results;

  while (beg != end) {
    if (beg->nick == nick)
      results.push_back(*beg);
    beg++;
  }

  return std::vector<contactdata>(results);
}

std::vector<contactdata> vomsdata::FindByVO(std::string vo)
{
  std::vector<contactdata>::iterator beg = servers.begin(), end = servers.end();
  std::vector<contactdata> results;

  while (beg != end) {
    if (beg->vo == vo)
      results.push_back(*beg);
    beg++;
  }

  return std::vector<contactdata>(results);
}

voms::voms(const voms &orig)
{
  version   = orig.version;
  siglen    = orig.siglen;
  signature = orig.signature;
  user      = orig.user;
  userca    = orig.userca;
  server    = orig.server;
  serverca  = orig.serverca;
  voname    = orig.voname;
  uri       = orig.uri;
  date1     = orig.date1;
  date2     = orig.date2;
  type      = orig.type;
  std       = orig.std;
  custom    = orig.custom;
  fqan      = orig.fqan;
  serial    = orig.serial;
  realdata  = calloc(1, sizeof(struct realdata));
  ((struct realdata *)realdata)->ac = AC_dup(((struct realdata *)orig.realdata)->ac);
  holder = X509_dup(orig.holder);
  
  ((struct realdata *)realdata)->attributes = 
    new std::vector<attributelist>(*(((struct realdata *)orig.realdata)->attributes));
}


voms::voms(): version(0), siglen(0), holder(NULL)
{
  realdata = (void *)calloc(1, sizeof(struct realdata));
}

voms &voms::operator=(const voms &orig)
{
  if (this == &orig)
    return *this;
 
  version   = orig.version;
  siglen    = orig.siglen;
  signature = orig.signature;
  user      = orig.user;
  userca    = orig.userca;
  server    = orig.server;
  serverca  = orig.serverca;
  voname    = orig.voname;
  uri       = orig.uri;
  date1     = orig.date1;
  date2     = orig.date2;
  type      = orig.type;
  std       = orig.std;
  custom    = orig.custom;
  fqan      = orig.fqan;
  serial    = orig.serial;
  if (((struct realdata *)realdata)->ac)
    AC_free(((struct realdata *)realdata)->ac);
  ((struct realdata *)realdata)->ac = AC_dup(((struct realdata *)orig.realdata)->ac);
  holder = X509_dup(orig.holder);
  delete ((struct realdata *)realdata)->attributes;
  ((struct realdata *)realdata)->attributes = 
    new std::vector<attributelist>(*(((struct realdata *)orig.realdata)->attributes));
  return *this;
}

voms::~voms()
{
  AC_free(((struct realdata *)realdata)->ac);
  delete (((struct realdata *)realdata)->attributes);
  free(realdata);
  X509_free(holder);
}

AC *voms::GetAC()
{
  return AC_dup(((struct realdata *)realdata)->ac);
}

std::vector<attributelist>& voms::GetAttributes()
{
  return *((struct realdata *)realdata)->attributes;
}

vomsdata::vomsdata(const vomsdata &orig) : ca_cert_dir(orig.ca_cert_dir),
                                           voms_cert_dir(orig.voms_cert_dir),
                                           duration(orig.duration),
                                           ordering(orig.ordering),
                                           servers(orig.servers),
                                           targets(orig.targets),
                                           error(orig.error),
                                           workvo(orig.workvo),
                                           extra_data(orig.extra_data),
                                           ver_type(orig.ver_type),
                                           serverrors(orig.serverrors),
                                           errmessage(orig.errmessage) {}

int getMajorVersionNumber(void) {return 1;}
int getMinorVersionNumber(void) {return 8;}
int getPatchVersionNumber(void) {return 0;}

void vomsdata::SetRetryCount(int retryCount)
{
  retry_count = retryCount;
}
