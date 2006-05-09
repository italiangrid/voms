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
#include "config.h"
#include "replace.h"

#ifndef NOGLOBUS
#include "globus_config.h"
#endif
#include <sys/types.h>
#include <netdb.h>
#include <dirent.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/wait.h>

#include <signal.h>

#ifndef NOGLOBUS
  /*#include "gssapi_compat.h"*/
#include "gssapi.h"
#include "globus_gss_assist.h"
#endif

#include <stdio.h>
#include <openssl/x509.h>
#include <openssl/asn1.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include "credentials.h"
}

#include <string>

#include "data.h"

#ifndef NOGLOBUS
#include "Client.h"
#endif

#include "voms_api.h"

#include <iostream>
#include <iomanip>
#include <fstream>

#include "sign.h"
#include "api_util.h"

#include "vomsxml.h"
#include "ccval.h"

static bool check_sig_ac(X509 *, void *, verror_type &);
static bool dncompare(const std::string &mut, const std::string &fixed);


static bool dncompare(const std::string &first, const std::string &second)
{
  if (first == second)
    return true;

  std::string::size_type userid = first.find(std::string("/USERID="));
  std::string::size_type uid = first.find(std::string("/UID="));

  std::string copy = first;
  if (userid != std::string::npos)
    return (copy.substr(0, userid) + "/UID=" + copy.substr(userid+8)) == second;
  else if (uid != std::string::npos)
    return (copy.substr(0, uid) + "/USERID=" + copy.substr(uid+5)) == second;

  return false;
}


bool
vomsdata::evaluate(AC_SEQ *acs, const std::string& subject, 
                   const std::string& ca, X509 *holder)
{
  bool ok = false;

  if (holder) {
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
  }

  return ok;
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
  int chain_length;
  X509_EXTENSION *ext;
  int index = 0;
  int nidf = 0, nidv = 0, nida = 0;
  int position = 0;
  char buf[1000];

  ca = subject = "";

  X509 *h = get_real_cert(cert, chain);
  if (!h) {
    seterror(VERR_IDCHECK, "Cannot discover holder from certificate chain!");
    return false;
  }

  *holder = (X509 *)ASN1_dup((int (*)())i2d_X509,(char * (*)())d2i_X509, (char *)h);
  if (!*holder) {
    seterror(VERR_MEM, "Cannot find enough memory to work!");
    return false;
  }

  ca = std::string(X509_NAME_oneline(X509_get_issuer_name(*holder), buf, 1000));
  subject = std::string(X509_NAME_oneline(X509_get_subject_name(*holder), buf, 1000));
  if (ca.empty() || subject.empty()) {
    seterror(VERR_IDCHECK, "Cannot discover CA name or DN from user's certificate.");
    return false;
  }

  /* object's nid */

  nidf = OBJ_txt2nid("incfile");
  nidv = OBJ_txt2nid("vo");
  nida = OBJ_txt2nid("acseq");

  /* seek for extensions in chain */

  index = X509_get_ext_by_NID(cert, nida, -1);
  if (index >= 0) {
    ext = X509_get_ext(cert,index);
    if (ext){
      *listnew = (AC_SEQ *)X509V3_EXT_d2i(ext);
      found = true;
    }
  }

  index = X509_get_ext_by_NID(cert, nidf, -1);
  if (index >= 0) {
    ext = X509_get_ext(cert,index);
    if (ext){
      extra_data = std::string((char *)(ext->value->data),ext->value->length);
      found = true;
    }
  }

  index = X509_get_ext_by_NID(cert, nidv, -1);
  if (index >= 0) {
    ext = X509_get_ext(cert,index);
    if (ext) {
      workvo = std::string((char *)(ext->value->data),ext->value->length);
      found = true;
    }
  }

  if (found && how != RECURSE_DEEP)
    return true;
  
  /*
   * May need to travel up the chain.
   */
  if (how != RECURSE_NONE) {
    
    chain_length = sk_X509_num(chain);
    
    while (position < chain_length) {
      
      cert = sk_X509_value(chain,position);
      
      index = X509_get_ext_by_NID(cert, nida, -1);
      if (index >= 0) {
        ext = X509_get_ext(cert, index);
        if (ext){
          *listnew = (AC_SEQ *)X509V3_EXT_d2i(ext);
          found = true;
        }
      }
      
      index = X509_get_ext_by_NID(cert, nidf, -1);
      if (index >= 0) {
        ext = X509_get_ext(cert,index);
        if (ext){
          extra_data = std::string((char *)(ext->value->data),ext->value->length);
          found = true;
        }
      }
      
      index = X509_get_ext_by_NID(cert, nidv, -1);
      if (index >= 0) {
        ext = X509_get_ext(cert,index);
        if (ext) {
          workvo = std::string((char *)(ext->value->data),ext->value->length);
          found = true;
        }
      }

      if (found && how != RECURSE_DEEP)
        return true;
      
      position++;
    } 
  }
  
  seterror(VERR_NOEXT, "VOMS extension not found!");
  return found;
}

bool 
vomsdata::verifydata(std::string &message, std::string subject, std::string ca, 
		    X509 *holder, voms &v)
{
  error = VERR_PARAM;
  if (message.empty() || subject.empty() || ca.empty() || !holder)
    return false;

  bool result = false;

  error = VERR_FORMAT;

  unsigned char *str  = (unsigned char *)(const_cast<char *>(message.data()));
  unsigned char *orig = str;

  AC   *tmp    = d2i_AC(NULL, &str, message.size());
  X509 *issuer = NULL;

  if (ver_type & VERIFY_SIGN) {
    issuer = check((void *)tmp);

    if (!issuer) {
      //      seterror(VERR_SIGN, "Cannot verify AC signature!");
      return false;
    }
  }

  if (tmp) {
    size_t off = str - orig;
    message = message.substr(off);

    result = verifyac(holder, issuer, tmp, v);
    if (!result) {
      //      seterror(VERR_VERIFY, "Cannot verify AC");
      return false;
    }
    else {
      v.ac = tmp;
      tmp = NULL;
    }
    
    if (result && (ver_type & VERIFY_ID)) {
      char buf[2048];
      /* check server subject */
      if (strcmp(X509_NAME_oneline(X509_get_subject_name(issuer), buf,2048),
                 v.server.c_str()) ||
          strcmp(X509_NAME_oneline(X509_get_issuer_name(issuer), buf,2048),
                 v.serverca.c_str())) {
        seterror(VERR_SERVER, "Mismatch between AC signer and AC issuer");
        result = false;
      }
    }
  }

  X509_free(issuer);
  AC_free(tmp);   
  
  if (result)
    v.holder = (X509 *)ASN1_dup((int (*) ())i2d_X509, 
				(char * (*)())d2i_X509, (char *)holder);
  return result;
}


bool 
vomsdata::verifydata(AC *ac, const std::string& subject, const std::string& ca, 
                     X509 *holder, voms &v)
{
  error = VERR_PARAM;
  if (!ac || subject.empty() || ca.empty() || !holder)
    return false;

  bool result = false;

  error = VERR_FORMAT;

  X509 *issuer = NULL;

  if (ver_type & VERIFY_SIGN) {
    issuer = check((void *)ac);

    if (!issuer) {
      //      seterror(VERR_SIGN, "Cannot verify AC signature!");
      return false;
    }
  }

  result = verifyac(holder, issuer, ac, v);
  if (!result) {
    //      seterror(VERR_VERIFY, "Cannot verify AC");
    return false;
  }
  else {
    v.ac = (AC *)ASN1_dup((int (*) ())i2d_AC,
                         (char * (*) ())d2i_AC, (char *)ac);
  }
  
  if (result && (ver_type & VERIFY_ID)) {
    char buf[2048];
    /* check server subject */
    if (strcmp(X509_NAME_oneline(X509_get_subject_name(issuer), buf,2048),
               v.server.c_str()) ||
        strcmp(X509_NAME_oneline(X509_get_issuer_name(issuer), buf,2048),
               v.serverca.c_str())) {
      seterror(VERR_SERVER, "Mismatch between AC signer and AC issuer");
      result = false;
    }
  }


  X509_free(issuer);
  
  if (result)
    v.holder = (X509 *)ASN1_dup((int (*) ())i2d_X509, 
				(char * (*)())d2i_X509, (char *)holder);
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

  int res = ASN1_verify((int (*)())i2d_AC_INFO, ac->sig_alg, ac->signature,
                        (char *)ac->acinfo, key);

  if (!res)
    seterror(VERR_SIGN, "Unable to verify AC signature");
  
  EVP_PKEY_free(key);

  return (res == 1);
}

X509 *
vomsdata::check(check_sig f, void *data)
{
  // This should not be used anymore.  Only left here for binary compatibility.
  return NULL;
}


X509 *
vomsdata::check(void *data)
{
  error = VERR_DIR;

  /* extract vo name from AC */
  
  AC * ac = (AC *)data;
  STACK_OF(AC_ATTR) * atts = ac->acinfo->attrib;
  int nid = OBJ_txt2nid("idatcap");
  int pos = X509at_get_attr_by_NID(atts, nid, -1);

  int nidc = OBJ_txt2nid("certseq");
  STACK_OF(X509_EXTENSION) *exts = ac->acinfo->exts;
  int posc = X509v3_get_ext_by_NID(exts, nidc, -1);

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
      hostname = voname.substr(cpos+3, (cpos2 - cpos - 3));
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

  DIR * dp = NULL;
  BIO * in = NULL;
  X509 * x = NULL;

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
  }

  if (in) 
    BIO_free(in);
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

  do {
    file.getline(buffer, buflen -1);
    if (!file)
      return false;

    len = strlen(buffer);
    int drop = 0;
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
      if (!readdn(file, subjcandidate, 1000) ||
          !readdn(file, issuercandidate, 1000)) {
        success = false;
        final = true;
        break;
      }

      char *realsubj = X509_NAME_oneline(X509_get_subject_name(current), NULL, 0);
      char *realiss  = X509_NAME_oneline(X509_get_issuer_name(current), NULL, 0);
      if (!dncompare(realsubj, subjcandidate) ||
          !dncompare(realiss, issuercandidate)) {
        do {
          file.getline(subjcandidate, 999);
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

  X509 *cert = (X509 *)ASN1_dup((int (*)())i2d_X509, (char * (*)())d2i_X509, (char *)sk_X509_value(certstack, 0));

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
  X509_STORE *ctx = NULL;
  X509_STORE_CTX *csc = NULL;
  X509_LOOKUP *lookup = NULL;
  int i = 0;

  csc = X509_STORE_CTX_new();
  ctx = X509_STORE_new();
  error = VERR_MEM;
  if (ctx && csc) {
    X509_STORE_set_verify_cb_func(ctx,cb);
#ifdef SIGPIPE
    signal(SIGPIPE,SIG_IGN);
#endif
    CRYPTO_malloc_init();
    if ((lookup = X509_STORE_add_lookup(ctx, X509_LOOKUP_file()))) {
      X509_LOOKUP_load_file(lookup, NULL, X509_FILETYPE_DEFAULT);
      if ((lookup=X509_STORE_add_lookup(ctx,X509_LOOKUP_hash_dir()))) {
        X509_LOOKUP_add_dir(lookup, ca_cert_dir.c_str(), X509_FILETYPE_PEM);
        ERR_clear_error();
        error = VERR_VERIFY;
        X509_STORE_CTX_init(csc,ctx,cert,NULL);
        i = X509_verify_cert(csc);
      }
    }
  }
  if (ctx) X509_STORE_free(ctx);
  if (csc) X509_STORE_CTX_free(csc);

  return (i != 0);
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
    X509_STORE_set_verify_cb_func(ctx,cb);
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
        index = X509_verify_cert(csc);
      }
    }
  }
  if (ctx) X509_STORE_free(ctx);
  if (csc) X509_STORE_CTX_free(csc);

  return (index != 0);
}


static int MS_CALLBACK 
cb(int ok, X509_STORE_CTX *ctx)
{
  char buf[256];

  if (!ok) {
    X509_NAME_oneline(X509_get_subject_name(ctx->current_cert),buf,256);
    if (ctx->error == X509_V_ERR_CERT_HAS_EXPIRED) ok=1;
    /* since we are just checking the certificates, it is
     * ok if they are self signed. But we should still warn
     * the user.
     */
    if (ctx->error == X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT) ok=1;
    /* Continue after extension errors too */
    if (ctx->error == X509_V_ERR_INVALID_CA) ok=1;
    if (ctx->error == X509_V_ERR_PATH_LENGTH_EXCEEDED) ok=1;
    if (ctx->error == X509_V_ERR_INVALID_PURPOSE) ok=1;
    if (ctx->error == X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT) ok=1;
  }
  return(ok);
}

bool
vomsdata::my_conn(const std::string &hostname, int port, const std::string &contact,
	int version, const std::string &command, std::string &u, std::string &uc,
	std::string &buf)
{
#ifndef NOGLOBUS
  GSISocketClient sock(hostname, port, version);

  sock.RedirectGSIOutput(stderr);
  sock.ServerContact(contact);
  sock.SetFlags(GSS_C_MUTUAL_FLAG | GSS_C_CONF_FLAG | GSS_C_INTEG_FLAG);

  if (!sock.Open()) {
    seterror(VERR_COMM, sock.GetError());
    sock.Close();
    return false;
  }
  
  u  = sock.own_subject;
  uc = sock.own_ca;
  //  sc = sock.peer_ca;
  //s  = sock.peer_subject;

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

  if (!sock.Receive(buf)) {
    seterror(VERR_COMM, sock.GetError());
    sock.Close();
    return false;
  }

  sock.Close();
  return true;
#else
  return false;
#endif
}

bool
vomsdata::contact(const std::string &hostname, int port, const std::string &contact,
	const std::string &command, std::string &buffer, std::string &username,
	std::string &ca)
{
#ifndef NOGLOBUS
  return my_conn(hostname, port, contact, globus(0), command, username, ca,
		 buffer);
#else
  return false;
#endif
}   
