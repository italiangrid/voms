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

#include "api_util.h"

extern "C" {
#include "config.h"
#include "replace.h"

#include <sys/types.h>
#include <netdb.h>
#include <dirent.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/wait.h>

#include <signal.h>

#include <stdio.h>
#include <openssl/x509.h>
#include <openssl/asn1.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include "credentials.h"
#include "sslutils.h"
}

#include <string>
#include <cstring>

#include "data.h"

#include "Client.h"

#include <iostream>
#include <iomanip>
#include <fstream>
#include <map>

#include "vomsxml.h"
#include "ccval.h"

#include "realdata.h"

#include "internal.h"
#include "normalize.h"

#ifndef VOMS_MAYBECONST
#if defined(D2I_OF)
#define VOMS_MAYBECONST const
#else
#define VOMS_MAYBECONST
#endif
#endif

extern proxy_verify_desc *setup_initializers(char *cadir);
extern void destroy_initializers(void *data);
static bool dncompare(const char *mut, const char *fixed);
static bool readdn(std::ifstream &file, char *buffer, int buflen);

extern std::map<vomsdata*, vomsspace::internal*> privatedata;
extern pthread_mutex_t privatelock;

static bool dncompare(const char *first, const char *second)
{
  if (!strcmp(first, second))
    return true;

  char *s1 = normalize(first);
  char *s2 = normalize(second);

  int res = strcmp(s1, s2);

  free(s1);
  free(s2);

  return res == 0;
}

bool
vomsdata::evaluate(AC_SEQ *acs, const std::string& subject, 
                   const std::string& ca, X509 *holder)
{
  bool ok = false;

  error = VERR_FORMAT;

  if (acs) {
    /* Only new types. bn may or may not be set. */
    int acnum = sk_AC_num(acs->acs);

    for (int i = 0; i < acnum; i++) {
      ok = false;
      voms v;
          
      AC *ac = (AC *)sk_AC_value(acs->acs, i);
      if (verifydata(ac, subject, ca, holder, v)) {
        data.push_back(v);
        ok = true;
      }

      if (!ok)
        break;
    }
  }
  else
    seterror(VERR_FORMAT, "AC not present in credentials.");

  return ok;
}


static X509_EXTENSION *get_ext(X509 *cert, const char *name)
{
  int nid   = OBJ_txt2nid(name);
  int index = X509_get_ext_by_NID(cert, nid, -1);

  if (index >= 0)
    return X509_get_ext(cert, index);
  else
    return NULL;
}

static bool findexts(X509 *cert , AC_SEQ **listnew, std::string &extra_data, std::string &workvo)
{
  X509_EXTENSION *ext;
  bool found = false;

  ext = get_ext(cert, "acseq");
  if (ext) {
    *listnew = (AC_SEQ *)X509V3_EXT_d2i(ext);
    found = true;
  }

  ext = get_ext(cert, "incfile");
  if (ext) {
    extra_data = std::string((char *)(ext->value->data),ext->value->length);
    found = true;
  }

  ext = get_ext(cert, "vo");
  if (ext) {
    workvo = std::string((char *)(ext->value->data),ext->value->length);
  }

  return found;
}

bool 
vomsdata::retrieve(X509 *cert, STACK_OF(X509) *chain, recurse_type how,
                   AC_SEQ **listnew, std::string &subject, std::string &ca, X509 **holder)
{
  bool found = false;

  if (!cert || (!chain && (how != RECURSE_NONE))) {
    seterror(VERR_PARAM, "Parameters unset!");
    return false;
  }

  /*
   * check credential and get the globus name
   */
  ca.clear();
  subject.clear();

  X509 *h = get_real_cert(cert, chain);
  if (!h) {
    seterror(VERR_IDCHECK, "Cannot discover holder from certificate chain!");
    return false;
  }

  *holder = X509_dup(h);

  if (!*holder) {
    seterror(VERR_MEM, "Cannot find enough memory to work!");
    return false;
  }

  char *buf = NULL;
  buf = X509_NAME_oneline(X509_get_issuer_name(*holder), NULL, 0);
  ca = std::string(buf ? buf : "" );
  OPENSSL_free(buf);

  buf = X509_NAME_oneline(X509_get_subject_name(*holder), NULL, 0);
  subject = std::string(buf ? buf : "");
  OPENSSL_free(buf);

  if (ca.empty() || subject.empty()) {
    seterror(VERR_IDCHECK, "Cannot discover CA name or DN from user's certificate.");
    return false;
  }

  /* object's nid */

  found = findexts(cert, listnew, extra_data, workvo);

  /*
   * RECURSE_DEEP means find *all* extensions, even if they are
   * superceded by newer ones.
   *
   * Because of this, the search cannot stop here but must continue.
   */
  if (found && how != RECURSE_DEEP)
    return true;
  
  /*
   * May need to travel up the chain.
   */
  if (how != RECURSE_NONE) {
    int chain_length = sk_X509_num(chain);
    int position = 0;
    
    while (position < chain_length) {  
      cert = sk_X509_value(chain,position);

      found |= findexts(cert, listnew, extra_data, workvo);      

      /*
       * RECURSE_DEEP means find *all* extensions, even if they are
       * superceded by newer ones.
       *
       * Because of this, the search cannot stop here but must continue.
       */
      if (found && how != RECURSE_DEEP)
        return true;
      
      position++;
    } 
  }
  
  seterror(VERR_NOEXT, "VOMS extension not found!");
  return found;
}

static bool verifyID(X509 *cert, const std::string &server, const std::string &serverca)
{
  bool result = true;

  /* check server subject */
  char *bufsub  = X509_NAME_oneline(X509_get_subject_name(cert), NULL, 0);
  char *bufiss  = X509_NAME_oneline(X509_get_issuer_name(cert), NULL, 0);
  if (!bufsub || !bufiss || 
      strcmp(bufsub, server.c_str()) ||
      strcmp(bufiss, serverca.c_str()))
    result = false;

  OPENSSL_free(bufsub);
  OPENSSL_free(bufiss);

  return result;
}

bool 
vomsdata::verifydata(std::string &message, UNUSED(std::string subject), 
                     UNUSED(std::string ca), 
                     X509 *holder, voms &v)
{
  error = VERR_PARAM;

  if (message.empty())
    return false;

  error = VERR_FORMAT;

  VOMS_MAYBECONST unsigned char *str  = (VOMS_MAYBECONST unsigned char *)(message.data());
  VOMS_MAYBECONST unsigned char *orig = str;

  AC   *tmp    = d2i_AC(NULL, &str, message.size());

  if (tmp) {
    size_t off = str - orig;
    message = message.substr(off);

    bool result = verifydata(tmp, subject, ca, holder, v);

    AC_free(tmp);

    return result;
  }

  return false;
}

bool 
vomsdata::verifydata(AC *ac, UNUSED(const std::string& subject), 
                     UNUSED(const std::string& ca), 
                     X509 *holder, voms &v)
{
  error = VERR_PARAM;
  if (!ac)
    return false;

  if (!holder && (ver_type & VERIFY_ID)) {
    error = VERR_NOIDENT;
    return false;
  }

  bool result = false;

  error = VERR_FORMAT;

  X509 *issuer = NULL;

  if (ver_type & VERIFY_SIGN) {
    issuer = check((void *)ac);

    if (!issuer) {
      seterror(VERR_SIGN, "Cannot verify AC signature!");
      return false;
    }
  }

  result = verifyac(holder, issuer, ac, verificationtime, v);
  if (!result) {
    X509_free(issuer);
    //    seterror(VERR_VERIFY, "Cannot verify AC");
    return false;
  }
  else {
    ((struct realdata *)v.realdata)->ac = AC_dup(ac);
  }
  
  if (result && (ver_type & VERIFY_ID)) {
    if (!verifyID(issuer, v.server, v.serverca)) {
      seterror(VERR_SERVER, "Mismatch between AC signer and AC issuer");
      result = false;
    }
  }

  X509_free(issuer);
  
  if (result)
    v.holder = holder ? X509_dup(holder) : NULL;
  return result;
}

bool vomsdata::check_sig_ac(X509 *cert, void *data)
{
  if (!cert || !data)
    return false;

  EVP_PKEY *key = X509_extract_key(cert);
  if (!key)
    return false;

  AC *ac = (AC *)data;

  int res = AC_verify(ac->sig_alg, ac->signature, (char *)ac->acinfo, key);

  if (!res)
    seterror(VERR_SIGN, "Unable to verify AC signature");
  
  EVP_PKEY_free(key);

  return (res == 1);
}

X509 *
vomsdata::check(void *data)
{
  error = VERR_DIR;

  /* extract vo name from AC */
  
  AC * ac = (AC *)data;
  const STACK_OF(AC_ATTR) * atts = ac->acinfo->attrib;

  int nid = OBJ_txt2nid("idatcap");
  int pos = X509at_get_attr_by_NID((const STACK_OF(X509_ATTRIBUTE)*)atts, nid, -1);

  if (!(pos >=0)) {
    seterror(VERR_DIR, "Unable to extract vo name from AC.");
    return NULL;
  }

  AC_ATTR * caps = sk_AC_ATTR_value(atts, pos);
  if(!caps) {
    seterror(VERR_DIR, "Unable to extract vo name from AC.");
    return NULL;
  }

  AC_IETFATTR * capattr = sk_AC_IETFATTR_value(caps->ietfattr, 0);
  if(!capattr) {
    seterror(VERR_DIR, "Unable to extract vo name from AC.");
    return NULL;
  }

  GENERAL_NAME * name = sk_GENERAL_NAME_value(capattr->names, 0);
  if(!name) {
    seterror(VERR_DIR, "Unable to extract vo name from AC.");
    return NULL;
  }
  
  std::string voname((const char *)name->d.ia5->data, 0, name->d.ia5->length);
  std::string::size_type cpos = voname.find("://");
  std::string hostname;

  if (cpos != std::string::npos) {
    std::string::size_type cpos2 = voname.find(":", cpos+1);

    if (cpos2 != std::string::npos) 
      hostname = voname.substr(cpos + 3, (cpos2 - cpos - 3));
    else {
      seterror(VERR_DIR, "Unable to determine hostname from AC.");
      return NULL;
    }
      
    voname = voname.substr(0, cpos);
  } 
  else {
    seterror(VERR_DIR, "Unable to extract vo name from AC.");
    return NULL;
  }

  /* check if the DN/CA file is installed for a given VO. */

  int nidc = OBJ_txt2nid("certseq");
  int posc = X509v3_get_ext_by_NID(ac->acinfo->exts, nidc, -1);

  if (posc >= 0) {
    std::string filecerts = voms_cert_dir + "/" + voname + "/" + hostname + ".lsc";
    std::ifstream file(filecerts.c_str());

    if (file)
      return check_from_file(ac, file, voname, filecerts);
  }

  /* check if able to find the signing certificate 
     among those specific for the vo or else in the vomsdir
     directory */
  return check_from_certs(ac, voname);
}

X509 *vomsdata::check_from_certs(AC *ac, const std::string& voname)
{
  bool found  = false;

  DIR  * dp = NULL;
  BIO  * in = NULL;
  X509 * x  = NULL;

  for(int i = 0; (i < 2 && !found); ++i) {
    
    std::string directory = voms_cert_dir + (i ? "" : "/" + voname);
    
    dp = opendir(directory.c_str());
    if (!dp) {
      if(!i) {
        continue;
      }
      else {
        break;
      }
    }

    while(struct dirent * de = readdir(dp)) {
      char * name = de->d_name;
      if (name) {
        in = BIO_new(BIO_s_file());

        if (in) {
          std::string temp = directory + "/" + name;

          if (BIO_read_filename(in, temp.c_str()) > 0) {
            x = PEM_read_bio_X509(in, NULL, 0, NULL);

            if (x) {
              if (check_sig_ac(x, ac)) {
                found = true;
                break;
              }
              else {
                X509_free(x);
                x = NULL;
              }
            }
          }
          BIO_free(in);
          in = NULL;
        }
      }
    }
    closedir(dp);
    dp = NULL;
  }

  BIO_free(in);
  if (dp)
    (void)closedir(dp);

  if (found) {
    if (!check_cert(x)) {
      X509_free(x);
      x = NULL;
    }
  }
  else
    seterror(VERR_SIGN, std::string("Cannot find certificate of AC issuer for vo ") + voname);
  
  return x;
}


static bool readdn(std::ifstream &file, char *buffer, int buflen)
{

  int len = 0;

  if (!file)
    return false;

  do {
    file.getline(buffer, buflen -1);
    if (!file)
      return false;

    len = strlen(buffer);
    int start = 0;
    while (buffer[start] && isspace(buffer[start]))
      start++;

    if (start == len) {
      len = 0;
      continue;
    }

    bool bounded = false;

    if (buffer[start] == '"') {
      start ++;
      bounded = true;
    }

    memmove(buffer, buffer+start, len - start);
    len -= start;

    start = 0;

    int mode;

    if (bounded) {
      mode = 1;
      do {
        switch(buffer[start]) {
          case '\\':
            mode = 2;
            start ++;
            break;
        case '"':
          start ++;

          if (mode != 2)
            bounded = false;
          break;
        case 0:
          break;
        default:
          start++;
          break;
        }
      } while (bounded);
    }

    if (start)
      buffer[start-1]=' ';

    while (len && isspace(buffer[len-1]))
      len--;
    buffer[len]='\0';

  } while (len == 0);

  return true;
}



X509 *vomsdata::check_from_file(AC *ac, std::ifstream &file, const std::string &voname, const std::string& filename)
{
  if (!file || !ac) {
    return NULL;
  }

  int nid = OBJ_txt2nid("certseq");
  STACK_OF(X509_EXTENSION) *exts = ac->acinfo->exts;
  int pos = X509v3_get_ext_by_NID(exts, nid, -1);
  X509_EXTENSION *ext=sk_X509_EXTENSION_value(exts, pos);

  AC_CERTS *certs = (AC_CERTS *)X509V3_EXT_d2i(ext);
  STACK_OF(X509) *certstack = certs->stackcert;

  bool success = false;
  bool final = false;

  do {
    success = true;

    for (int i = 0; i < sk_X509_num(certstack); i++) {
      if (!file)
        break;

      char subjcandidate[1000];
      char issuercandidate[1000];

      X509 *current = sk_X509_value(certstack, i);
      if (!readdn(file, subjcandidate, 999) ||
          !readdn(file, issuercandidate, 999)) {
        success = false;
        final = true;
        break;
      }

      subjcandidate[999] = issuercandidate[999] = '\0';

      char *realsubj = X509_NAME_oneline(X509_get_subject_name(current), NULL, 0);
      char *realiss  = X509_NAME_oneline(X509_get_issuer_name(current), NULL, 0);
      if (!dncompare(realsubj, subjcandidate) ||
          !dncompare(realiss, issuercandidate)) {
        do {
          file.getline(subjcandidate, 999);
          subjcandidate[999] = '\0';
        } while (file && strcmp(subjcandidate, "------ NEXT CHAIN ------"));
        success = false;
        break;
      }
      OPENSSL_free(realsubj);
      OPENSSL_free(realiss);
    }
    if (success || !file)
      final = true;

  } while (!final);

  file.close();

  if (!success) {
    AC_CERTS_free(certs);
    seterror(VERR_SIGN, "Unable to match certificate chain against file: " + filename);
    return NULL;
  }
                  
  /* check if able to find the signing certificate 
     among those specific for the vo or else in the vomsdir
     directory */

  X509 *cert = X509_dup(sk_X509_value(certstack, 0));

  bool found = false;

  if (check_sig_ac(cert, ac))
    found = true;
  else
    seterror(VERR_SIGN, "Unable to verify signature!");

  if (found) {
    if (!check_cert(certstack)) {
      cert = NULL;
      seterror(VERR_SIGN, "Unable to verify certificate chain.");
    }
  }
  else
    seterror(VERR_SIGN, std::string("Cannot find certificate of AC issuer for vo ") + voname);

  AC_CERTS_free(certs);
  return cert;
}

bool
vomsdata::check_cert(X509 *cert)
{
  STACK_OF(X509) *stack = sk_X509_new_null();

  if (stack) {
    sk_X509_push(stack, cert);

    bool result = check_cert(stack);

    sk_X509_free(stack);

    return result;
  }

  return false;
}

bool
vomsdata::check_cert(STACK_OF(X509) *stack)
{
  X509_STORE *ctx = NULL;
  X509_STORE_CTX *csc = NULL;
  X509_LOOKUP *lookup = NULL;
  int index = 0;

  csc = X509_STORE_CTX_new();
  ctx = X509_STORE_new();
  error = VERR_MEM;
  if (ctx && csc) {
    proxy_verify_desc *pvd = setup_initializers(strdup((char*)ca_cert_dir.c_str()));

    X509_STORE_set_verify_cb_func(ctx,proxy_verify_callback);
#ifdef SIGPIPE
    signal(SIGPIPE,SIG_IGN);
#endif
    CRYPTO_malloc_init();
    if ((lookup = X509_STORE_add_lookup(ctx, X509_LOOKUP_file()))) {
      X509_LOOKUP_load_file(lookup, NULL, X509_FILETYPE_DEFAULT);

      if ((lookup=X509_STORE_add_lookup(ctx,X509_LOOKUP_hash_dir()))) {
        X509_LOOKUP_add_dir(lookup, ca_cert_dir.c_str(), X509_FILETYPE_PEM);

        for (int i = 1; i < sk_X509_num(stack); i++)
          X509_STORE_add_cert(ctx,sk_X509_value(stack, i));

        ERR_clear_error();
        error = VERR_VERIFY;
        X509_STORE_CTX_init(csc, ctx, sk_X509_value(stack, 0), NULL);
        X509_STORE_CTX_set_ex_data(csc, PVD_STORE_EX_DATA_IDX, pvd);
        index = X509_verify_cert(csc);
      }
    }
    destroy_initializers(pvd);
  }
  X509_STORE_free(ctx);

  if (csc)
    X509_STORE_CTX_free(csc);

  return (index != 0);
}

bool
vomsdata::contact(const std::string &hostname, int port, UNUSED(const std::string &contact),
	const std::string &command, std::string &buf, std::string &u, std::string &uc,
                  int timeout)
{
  GSISocketClient sock(hostname, port);

  char *cacert = NULL;
  char *certdir = NULL;
  char *outfile = NULL;
  char *certfile = NULL;
  char *keyfile = NULL;
  bool noregen = false;

  X509           *ucert = NULL;
  STACK_OF(X509) *cert_chain = NULL;
  EVP_PKEY       *upkey = NULL;

  pthread_mutex_lock(&privatelock);
  vomsspace::internal *data = privatedata[this];
  pthread_mutex_unlock(&privatelock);

  ucert      = data->cert;
  cert_chain = data->chain;
  upkey      = data->key;

  if (!ucert || !upkey) {
    if (determine_filenames(&cacert, &certdir, &outfile, &certfile, &keyfile, noregen)) {
      if (!load_credentials(certfile, keyfile, &ucert, &cert_chain, &upkey, NULL)) {
        seterror(VERR_NOIDENT, "Cannot load credentials.");
        return false;
      }
    }
    else {
      seterror(VERR_NOIDENT, "Cannot discover credentials.");
      return false;
    }
  }
  sock.LoadCredentials(ca_cert_dir.c_str(), ucert, cert_chain, upkey);
  //  sock.SetFlags(GSS_C_MUTUAL_FLAG | GSS_C_CONF_FLAG | GSS_C_INTEG_FLAG);
  sock.SetTimeout(timeout);

  if (!sock.Open()) {
    seterror(VERR_COMM, sock.GetError());
    sock.Close();
    return false;
  }
  
  u  = sock.own_subject;
  uc.clear();

  if (u.empty()) {
    seterror(VERR_NOIDENT, sock.GetError());
    sock.Close();
    return false;
  }

  if (!sock.Send(command)) {
    seterror(VERR_COMM, sock.GetError());
    sock.Close();
    return false;
  }

  std::string msg;
  bool ret;

  do {
    ret = sock.Receive(msg);
    if (!ret) {
      seterror(VERR_COMM, sock.GetError());
      sock.Close();
      return false;
    }
    buf += msg;
  } while (ret && ! msg.empty());

  sock.Close();
  return true;
}
