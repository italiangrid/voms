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

#ifndef NOGLOBUS
#define NOGLOBUS
#endif

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
#include <openssl/objects.h>
#include <openssl/asn1.h>
#include <openssl/evp.h>
#include <openssl/pkcs12.h>

#include "credentials.h"
#include "sslutils.h"
#include "gssapi_compat.h"

#ifndef NOGLOBUS
#ifdef HAVE_GLOBUS_MODULE_ACTIVATE
#include <globus_module.h>
#include <globus_openssl.h>
#endif
#else
#include <openssl/crypto.h>
#endif
extern int InitProxyCertInfoExtension(int);
}

#include <cstring>
#include <fstream>
#include <iostream>
#include <map>

#include <voms_api.h>
#include "data.h"
#include "vomsxml.h"

#include "realdata.h"

#include "internal.h"

extern bool retrieve(X509 *cert, STACK_OF(X509) *chain, recurse_type how, 
		     std::string &buffer, std::string &vo, std::string &file, 
		     std::string &subject, std::string &ca, verror_type &error);

static std::string parse_commands(const std::string& commands);

extern int AC_Init(void);

std::map<vomsdata*, vomsspace::internal*> privatedata;
pthread_mutex_t privatelock = PTHREAD_MUTEX_INITIALIZER;

static bool initialized = false;

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
                                                                  retry_count(1),
                                                                  verificationtime(0),
                                                                  vdp(NULL)
{
   if (!initialized) {
     initialized = true;
#ifdef NOGLOBUS
     SSL_library_init();
     OpenSSL_add_all_algorithms();
     ERR_load_crypto_strings();
     OpenSSL_add_all_ciphers();

     (void)AC_Init();
     InitProxyCertInfoExtension(1);
#endif
     PKCS12_PBE_add();
   }

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

  vomsspace::internal *data = new vomsspace::internal();
  pthread_mutex_lock(&privatelock);
  privatedata[this] = data;
  pthread_mutex_unlock(&privatelock);
}


vomsdata::~vomsdata()
{
  pthread_mutex_lock(&privatelock);
  vomsspace::internal *data = privatedata[this];
  (void)privatedata.erase(this);
  pthread_mutex_unlock(&privatelock);
  delete data;

}

std::string vomsdata::ServerErrors(void)
{
  std::string err = serverrors;
  serverrors.clear();

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
  ordering.clear();
}

void vomsdata::Order(std::string att)
{
  ordering += (ordering.empty() ? ""  : ",") + att;
}

bool vomsdata::ContactRaw(std::string hostname, int port, std::string servsubject, std::string command, std::string &raw, int& version) {
  return ContactRaw(hostname, port, servsubject, command, raw, version, -1);
}

bool vomsdata::InterpretOutput(const std::string &message, std::string& output)
{
  answer a;
  
  if (XML_Ans_Decode(message, a)) {
    bool result = true;

    if (!a.ac.empty()) {
      output = a.ac;
      if (a.errs.size() != 0) {
        std::vector<errorp>::const_iterator end = a.errs.end();
        for (std::vector<errorp>::const_iterator i = a.errs.begin();
             i != end; ++i) {
          serverrors += i->message;
          if (i->num > ERROR_OFFSET)
            result = false;
          if (i->num == WARN_NO_FIRST_SELECT)
            seterror(VERR_ORDER, "Cannot put requested attributes in the specified order.");
        }
      }
    }
    else if (!a.data.empty()) {
      output = a.data;
    }
    if (!result && ver_type) {
      seterror(VERR_SERVERCODE, "The server returned an error.");
      return false;
    }
  }
  else {
    seterror(VERR_FORMAT, "Server Answer was incorrectly formatted.");
    return false;
  }

  return true;
}

bool vomsdata::ContactRaw(std::string hostname, int port, std::string servsubject, std::string command, std::string &raw, int& version, int timeout)
{
  std::string buffer;
  std::string subject, ca;
  std::string lifetime;

  std::string comm;
  std::string targs;

  version = 1;

  /* Try REST connection first */
  bool ret = ContactRESTRaw(hostname, port, command, raw, version, timeout);

  if (ret)
    return ret;

  std::vector<std::string>::const_iterator end = targets.end();
  std::vector<std::string>::const_iterator begin = targets.begin();
  for (std::vector<std::string>::const_iterator i = begin; i != end; ++i) {
    if (i == begin)
      targs = *i;
    else
      targs += std::string(",") + *i;
  }

  comm = XML_Req_Encode(command, ordering, targs, duration);

  if (!contact(hostname, port, servsubject, comm, buffer, subject, ca, timeout))
    return false;

  version = 1;
  return InterpretOutput(buffer, raw);
}

static X509 *get_own_cert()
{
  char *certname = NULL;

  if (determine_filenames(NULL, NULL, NULL, &certname, NULL, 0)) {
    X509 *cert = NULL;

    if (load_credentials(certname, NULL, &cert, NULL, NULL, NULL))
      return cert;
  }

  return NULL;
}


bool vomsdata::ContactRESTRaw(const std::string& hostname, int port, const std::string& command, std::string& raw, UNUSED(int version), int timeout)
{
  std::string temp;

  std::string realCommand = "GET /generate-ac?fqans="+ parse_commands(command);

  realCommand += "&lifetime="+ stringify(duration, temp);

  if (!ordering.empty())
    realCommand +="&order=" + ordering;

  if (targets.size() != 0) {
    std::string targs;

    std::vector<std::string>::const_iterator end = targets.end();
    std::vector<std::string>::const_iterator begin = targets.begin();

    for (std::vector<std::string>::const_iterator i = targets.begin(); i != end; ++i) {
      if (i == begin)
        targs = *i;
      else
        targs += std::string(",") + *i;
    }

    realCommand +="&targets="+targs;
  }

  realCommand += std::string(" HTTP/1.0\n") + 
    "User-Agent: voms APIs 2.0\nAccept: */*\nHost: "+
    hostname+":"+ stringify(port,temp) +"\n\n";

  std::string user, userca, output;
  bool res = contact(hostname, port, "", realCommand, output, user, userca, timeout);

  bool ret = false;

  if (res) {
    std::string::size_type pos = output.find("<?xml");

    if (pos != std::string::npos)
      ret = InterpretOutput(output.substr(pos), raw);

    if (ret) 
      if (!(output.substr(0,12) == "HTTP/1.1 200"))
        return false;
    
    return ret;
  }

  return ret;
}

bool vomsdata::Contact(std::string hostname, int port, std::string servsubject, std::string command) {
  return Contact(hostname, port, servsubject, command, -1);
}


bool vomsdata::Contact(std::string hostname, int port, UNUSED(std::string servsubject), std::string command, int timeout)
{
  std::string subject, ca;
  char *s = NULL, *c = NULL;

  std::string message;
  bool result = false;
  int version;

  for (int i=0; i < retry_count; ++i)
  {
    if (ContactRaw(hostname, port, servsubject, command, message, version, timeout)) {

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
}


bool vomsdata::Retrieve(FILE *file, recurse_type how)
{
  X509 *x = NULL;
  STACK_OF(X509) *chain = NULL;
  bool res = false;
  
  if (file) {
    if (load_certificate_from_file(file, &x , &chain)) {
      res = Retrieve(x, chain, how);
    }
    else 
      seterror(VERR_PARAM, "Cannot load credentials.");
  }
  else
    seterror(VERR_PARAM, "File parameter invalid.");

  if (chain)
    sk_X509_pop_free(chain, X509_free);

  if (x)
    X509_free(x);

  return res;
}

bool vomsdata::RetrieveFromCred(gss_cred_id_t cred, recurse_type how)
{
  X509 *cert;
  STACK_OF(X509) *chain;

  chain = ((gss2_cred_id_desc *)cred)->cred_handle->cert_chain;
  cert = ((gss2_cred_id_desc *)cred)->cred_handle->cert;

  return Retrieve(cert, chain, how);
}

bool vomsdata::RetrieveFromCtx(UNUSED(gss_ctx_id_t cred), UNUSED(recurse_type how))
{
  return false;
}

bool vomsdata::RetrieveFromProxy(recurse_type how)
{
  char *outfile = NULL;

  if (determine_filenames(NULL, NULL, &outfile, NULL, NULL, 0)) {
    X509 *cert = NULL;
    STACK_OF(X509) *stk = NULL;
    EVP_PKEY *key = NULL;

    if (load_credentials(outfile, outfile, &cert, &stk, &key, NULL)) {
      return Retrieve(cert, stk, how);
    }
  }
  return false;
}

bool vomsdata::Retrieve(X509_EXTENSION *ext)
{
  verify_type v = ver_type;
  ver_type = (verify_type)((int)ver_type & (~VERIFY_ID));

  bool ret = evaluate((AC_SEQ*)X509V3_EXT_d2i(ext), "", "", NULL);

  ver_type = v;

  return ret;
}

bool vomsdata::Retrieve(AC *ac)
{
  verify_type v = ver_type;

  ver_type = (verify_type)((int) ver_type & (~VERIFY_ID));

  voms vv;

  bool ret = verifydata(ac, "", "", NULL, vv);

  if (ret)
    data.push_back(vv);

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

  buffer = Decode(buffer);

  if (buffer.empty()) {
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
    buffer.clear();
    return true;
  }


  std::vector<voms>::const_iterator end = data.end();

  for (std::vector<voms>::const_iterator v=data.begin(); v != end; ++v) {
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

  buffer = Encode(result, 0);

  if (!buffer.empty())
    return true;
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

bool vomsdata::loadfile(std::string filename, UNUSED(uid_t uid), UNUSED(gid_t gid))
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

bool vomsdata::loadfile0(std::string filename, UNUSED(uid_t uid), UNUSED(gid_t gid))
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
    dir = "/etc/vomses";

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
  std::vector<contactdata>::const_iterator beg = servers.begin(), end = servers.end();
  std::vector<contactdata> results;

  while (beg != end) {
    if (beg->nick == nick)
      results.push_back(*beg);
    ++beg;
  }

  return std::vector<contactdata>(results);
}

std::vector<contactdata> vomsdata::FindByVO(std::string vo)
{
  std::vector<contactdata>::const_iterator beg = servers.begin(), end = servers.end();
  std::vector<contactdata> results;

  while (beg != end) {
    if (beg->vo == vo)
      results.push_back(*beg);
    ++beg;
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
  vp = NULL;
}

voms::voms(): version(0), siglen(0), holder(NULL), vp(NULL)
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
  vp        = NULL;
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
                                           data(orig.data),
                                           workvo(orig.workvo),
                                           extra_data(orig.extra_data),
                                           ver_type(orig.ver_type),
                                           serverrors(orig.serverrors),
                                           errmessage(orig.errmessage),
                                           retry_count(orig.retry_count),
                                           verificationtime(orig.verificationtime),
                                           vdp(NULL)
{}

extern "C" {
int getVOMSMajorVersionNumber(void) {return 2;}
int getVOMSMinorVersionNumber(void) {return 0;}
int getVOMSPatchVersionNumber(void) {return 0;}
}

void vomsdata::SetRetryCount(int retryCount)
{
  retry_count = retryCount;
}

void vomsdata::SetVerificationTime(time_t thistime)
{
  verificationtime = thistime;
}

std::vector<std::string> voms::GetTargets()
{
  AC *ac = GetAC();

  std::vector<std::string> targets;

  STACK_OF(X509_EXTENSION) *exts = ac->acinfo->exts;

  int nid = OBJ_txt2nid("idceTargets");
  int pos = X509v3_get_ext_by_NID(exts, nid, -1);

  if (pos >= 0) {
    X509_EXTENSION *ex = sk_X509_EXTENSION_value(exts, pos);
    AC_TARGETS *target = (AC_TARGETS *)X509V3_EXT_d2i(ex);

    if (target != NULL) {
      for (int i = 0; i < sk_AC_TARGET_num(target->targets); i++) {
        AC_TARGET *name = NULL;
        name = sk_AC_TARGET_value(target->targets, i);
        if (name->name->type == GEN_URI)
          targets.push_back(std::string((char*)(name->name->d.ia5->data), 
                                        name->name->d.ia5->length));
      }
    }
    AC_TARGETS_free(target);
  }

  AC_free(ac);
  return targets;
}

bool vomsdata::LoadCredentials(X509 *cert, EVP_PKEY *pkey, STACK_OF(X509) *chain)
{
  pthread_mutex_lock(&privatelock);
  vomsspace::internal *data = privatedata[this];
  pthread_mutex_unlock(&privatelock);

  /* The condition below should never be true. */
  if (!data)
    return false;

  if (cert) {
    X509_free(data->cert);
    data->cert = X509_dup(cert);
  }

  if (pkey) {
    EVP_PKEY_free(data->key);
    data->key = EVP_PKEY_dup(pkey);
  }

  /* sk_dup does *not* duplicate the stack content.  Only the
     stack itself. */
  /* So, do the duplication by hand. */
  if (chain) {
    sk_X509_pop_free(data->chain, X509_free);
    data->chain = sk_X509_new_null();

    if (data->chain) {
      for (int i =0; i < sk_X509_num(chain); i++) {
        X509 *newcert = X509_dup(sk_X509_value(chain, i));
        if (!newcert) {
          sk_X509_pop_free(data->chain, X509_free);
          data->chain = NULL;
          break;
        }
        
        sk_X509_push(data->chain, newcert);
      }
    }
  }

  if ((cert && !data->cert) || (pkey && !data->key) || 
      (chain && !data->chain)) {
    X509_free(cert);
    EVP_PKEY_free(pkey);
    sk_X509_pop_free(data->chain, X509_free);

    data->cert = NULL;
    data->chain = NULL;
    data->key = NULL;

    return false;
  }
  return true;
}


static void change(std::string &name, const std::string& from, const std::string& to) 
{
  std::string::size_type pos = name.find(from);

  while (pos != std::string::npos) {
    name = name.substr(0, pos) + to + name.substr(pos+from.length());
    pos = name.find(from, pos+1);
  }
}

static std::string parse_commands(const std::string& commands)
{
  if (commands[0] == '/')
    return commands;

  if (commands[0] == 'A')
    return std::string("all");

  std::string temp = commands;

  change(temp, ":", "/Role=");
  change(temp, "G/", "/");
  change(temp, "B/", "/");
  change(temp, "R/", "/Role=");

  return temp;
}
