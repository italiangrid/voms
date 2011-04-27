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

#include "config.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/stack.h>
#include <openssl/evp.h>
#include <openssl/bio.h>

#include "vomsproxy.h"
#include "myproxycertinfo.h"
#include "sslutils.h"
#include "doio.h"

static char *readfromfile(char *file, int *size, int *warning);
static void setWarning(int *warning, int value);
static void setAdditional(void **additional, void *data);
static X509_EXTENSION *set_KeyUsageFlags(int flags);
static int get_KeyUsageFlags(X509 *cert);
static X509_EXTENSION *set_ExtendedKeyUsageFlags(char *flagnames);
static char *getBitName(char**string);
static int getBitValue(char *bitname);
static int convertMethod(char *bits, int *warning, void **additional);
static X509_EXTENSION *get_BasicConstraints(int ca);

struct VOMSProxyArguments *VOMS_MakeProxyArguments()
{
  return (struct VOMSProxyArguments*)calloc(1, sizeof(struct VOMSProxyArguments));
}

void VOMS_FreeProxyArguments(struct VOMSProxyArguments *args)
{
  free(args);
}

void VOMS_FreeProxy(struct VOMSProxy *proxy)
{
  if (proxy) {
    X509_free(proxy->cert);
    sk_X509_pop_free(proxy->chain, X509_free);
    EVP_PKEY_free(proxy->key);
    free(proxy);
  }
}

struct VOMSProxy *VOMS_AllocProxy() 
{
  return (struct VOMSProxy*)calloc(1, sizeof(struct VOMSProxy));
}

int VOMS_WriteProxy(const char *filename, struct VOMSProxy *proxy)
{
  int ret = -1;
  int fd = -1;
  int retry = 3;
  BIO *bp = NULL;

  while (fd < 0 && retry > 0) {
    unlink(filename);
    fd  = open(filename, O_WRONLY|O_CREAT|O_EXCL|O_TRUNC, 0600);
    retry --;
  }

#ifndef WIN32
  if (fd != -1) {
    if (fchmod(fd, S_IRUSR|S_IWUSR) < 0) {
      close(fd);
      return -1;
    }
  }
#endif

  if (fd != -1) {
    if ((bp = BIO_new_fd(fd, BIO_NOCLOSE)) != NULL) {
      ret = proxy_marshal_bp(bp, proxy->cert, proxy->key, NULL, proxy->chain);
      BIO_free(bp);
    }
    close(fd);
  }

  return ret;
}


static int kpcallback(int UNUSED(p), int UNUSED(n)) 
{
  return 0;
}

#define SET_EXT(ex)  (!sk_X509_EXTENSION_push(extensions, (ex)) ? \
   (PRXYerr(PRXYERR_F_PROXY_SIGN, PRXYERR_R_CLASS_ADD_EXT), 0) : \
   ((ex = ((X509_EXTENSION*)NULL)), 1))

struct VOMSProxy *VOMS_MakeProxy(struct VOMSProxyArguments *args, int *warning, void **additional) 
{
  char *value = NULL;

  X509 * ncert = NULL;
  EVP_PKEY * npkey = NULL;
  X509_REQ * req = NULL;
  STACK_OF(X509_EXTENSION) * extensions = NULL;
  int ku_flags = 0;
  char *policy = NULL;

  X509_EXTENSION *ex1 = NULL, *ex2 = NULL, *ex3 = NULL, 
    *ex4 = NULL, *ex5 = NULL, *ex6 = NULL, *ex7 = NULL, 
    *ex8 = NULL, *ex9 = NULL, *ex10 = NULL, *ex11 = NULL,
    *ex12 = NULL, *ex13 = NULL;

  int i = 0;
  
  struct VOMSProxy *proxy = NULL;

  static int init = 0;

  int (*cback)();

  if (!init) {
    InitProxyCertInfoExtension(1);
    init = 1;
  }

  setWarning(warning, PROXY_NO_ERROR);

  if (args->callback)
    cback = args->callback;
  else
    cback = kpcallback;

  
  if (args->proxyrequest == NULL) {
    if (proxy_genreq(args->cert, &req, &npkey, args->bits, 
                     args->newsubject ? args->newsubject : NULL, 
                     (int (*)())cback))
      goto err;
  }
  else
    req = args->proxyrequest;

  /* initialize extensions stack */

  if ((extensions = sk_X509_EXTENSION_new_null()) == NULL) {
    PRXYerr(PRXYERR_F_PROXY_SIGN, PRXYERR_R_CLASS_ADD_EXT);
    goto err;
  }

  /* Add passed extensions */
  if (args->extensions) {
    int proxyindex;

    for (proxyindex = 0; proxyindex < sk_X509_EXTENSION_num(args->extensions); proxyindex++) {
      X509_EXTENSION *ext = X509_EXTENSION_dup(sk_X509_EXTENSION_value(args->extensions, i));
      if (ext) {
        if (!sk_X509_EXTENSION_push(extensions, ext)) {
          X509_EXTENSION_free(ext);
          PRXYerr(PRXYERR_F_PROXY_SIGN, PRXYERR_R_CLASS_ADD_EXT);
          goto err;
        }
      }
      else {
        PRXYerr(PRXYERR_F_PROXY_SIGN, PRXYERR_R_CLASS_ADD_EXT);
        goto err;
      }
    }
  }
  /* Add proxy extensions */

  /* voms extension */
  
  if (args->datalen) {
    if ((ex1 = CreateProxyExtension("voms", args->data, args->datalen, 0)) == NULL) {
      PRXYerr(PRXYERR_F_PROXY_SIGN, PRXYERR_R_CLASS_ADD_EXT);
      goto err;
    }

    if (!SET_EXT(ex1))
      goto err;
  }

  /* include extension */

  if (args->filename) {

    int filesize;
    char *filedata = readfromfile(args->filename, &filesize, warning);

    if (filedata) {
      if ((ex3 = CreateProxyExtension("incfile", filedata, filesize, 0)) == NULL) {
        PRXYerr(PRXYERR_F_PROXY_SIGN, PRXYERR_R_CLASS_ADD_EXT);
        free(filedata);
        goto err;
      }
      
      free(filedata);
      if (!SET_EXT(ex3))
        goto err;
    }
    else {
      setAdditional(additional, args->filename);
      goto err;
    }
  }

  /* AC extension  */

  if (args->aclist) {

    if ((ex5 = X509V3_EXT_conf_nid(NULL, NULL, OBJ_txt2nid("acseq"), (char *)args->aclist)) == NULL) {
      PRXYerr(PRXYERR_F_PROXY_SIGN, PRXYERR_R_CLASS_ADD_EXT);
      goto err;
    }
    
    if (!SET_EXT(ex5))
      goto err;
  }

  /* keyUsage extension */

  if (args->keyusage) {
    ku_flags = convertMethod(args->keyusage, warning, additional);
    if (ku_flags == -1) {
      PRXYerr(PRXYERR_F_PROXY_SIGN, PRXYERR_R_CLASS_ADD_EXT);
      goto err;
    }
  }
  else if (args->selfsigned) {
    ku_flags = X509v3_KU_DIGITAL_SIGNATURE | X509v3_KU_KEY_CERT_SIGN |
      X509v3_KU_CRL_SIGN;
  }
  else {
    ku_flags = get_KeyUsageFlags(args->cert);
    ku_flags &= ~X509v3_KU_KEY_CERT_SIGN;
    ku_flags &= ~X509v3_KU_NON_REPUDIATION;
  }

  if ((ex8 = set_KeyUsageFlags(ku_flags)) == NULL) {
    PRXYerr(PRXYERR_F_PROXY_SIGN, PRXYERR_R_CLASS_ADD_EXT);
    goto err;
  }

  X509_EXTENSION_set_critical(ex8, 1);

  if (!SET_EXT(ex8))
    goto err;

  /* netscapeCert extension */
  if (args->netscape) {

    if ((ex9 = X509V3_EXT_conf_nid(NULL, NULL, NID_netscape_cert_type, args->netscape)) == NULL) {
      /*      PRXYerr(PRXYERR_F_PROXY_SIGN, PRXYERR_R_CLASS_ADD_EXT); */
      goto err;
    }

    if (!SET_EXT(ex9))
      goto err;
  }

  /* extended key usage */

  if (args->exkusage) {
    if ((ex10 = set_ExtendedKeyUsageFlags(args->exkusage)) == NULL) {
      PRXYerr(PRXYERR_F_PROXY_SIGN, PRXYERR_R_CLASS_ADD_EXT);
      setWarning(warning, PROXY_ERROR_UNKNOWN_EXTENDED_BIT);
      setAdditional(additional,args->exkusage);
      goto err;
    }

    if (!SET_EXT(ex10))
      goto err;
  }

  /* Basic Constraints */

  if ((ex12 = get_BasicConstraints(args->selfsigned ? 1 : 0)) == NULL) {
      PRXYerr(PRXYERR_F_PROXY_SIGN, PRXYERR_R_CLASS_ADD_EXT);
      goto err;
    }

  X509_EXTENSION_set_critical(ex12, 1);

  if (!SET_EXT(ex12))
    goto err;
 
  /* vo extension */
  
  if (strlen(args->voID)) {
    if ((ex4 = CreateProxyExtension("vo", args->voID, strlen(args->voID), 0)) == NULL) {
      PRXYerr(PRXYERR_F_PROXY_SIGN,PRXYERR_R_CLASS_ADD_EXT);
      goto err;
    }
    
    if (!SET_EXT(ex4))
      goto err;
  }
  
  /* authority key identifier and subject key identifier extension */

  {
    X509V3_CTX ctx;
    
    X509V3_set_ctx(&ctx, (args->selfsigned ? NULL : args->cert), NULL, req, NULL, 0);

    if (args->selfsigned) {
      X509 *tmpcert = NULL;
      ex13 = X509V3_EXT_conf_nid(NULL, &ctx, NID_subject_key_identifier, "hash");

      if (!ex13) {
        PRXYerr(PRXYERR_F_PROXY_SIGN,PRXYERR_R_CLASS_ADD_EXT);
        goto err;
      }
          
      if (!SET_EXT(ex13))
        goto err;

      tmpcert = X509_new();
      if (tmpcert) {
        EVP_PKEY *key = X509_REQ_get_pubkey(req);
        X509_set_pubkey(tmpcert, key);
        X509_add_ext(tmpcert, ex13, -1);
        X509V3_set_ctx(&ctx, tmpcert, tmpcert, req, NULL, 0);
        ex11 = X509V3_EXT_conf_nid(NULL, &ctx, NID_authority_key_identifier, "keyid");
        X509_free(tmpcert);
        EVP_PKEY_free(key);
      }
      else
        ex11 = NULL;
    }
    else {
      ex11 = X509V3_EXT_conf_nid(NULL, &ctx, NID_authority_key_identifier, "keyid");
    }

    if (!ex11) {
      PRXYerr(PRXYERR_F_PROXY_SIGN,PRXYERR_R_CLASS_ADD_EXT);
      goto err;
    }
          
    if (!SET_EXT(ex11))
      goto err;
  }

  /* class_add extension */

#ifdef CLASS_ADD
  
  if (class_add_buf && class_add_buf_len > 0) {
    if ((ex2 = proxy_extension_class_add_create((void *)args->class_add_buf, args->class_add_buf_len)) == NULL) {
      PRXYerr(PRXYERR_F_PROXY_SIGN,PRXYERR_R_CLASS_ADD_EXT);
      goto err;
    }
    
    if (!SET_EXT(ex2))
      goto err;
  }

#endif

  /* PCI extension */
  
  if (args->proxyversion>=3) {
    myPROXYPOLICY *                     proxypolicy;
    myPROXYCERTINFO *                   proxycertinfo = NULL;
    ASN1_OBJECT *                       policy_language;

    /* getting contents of policy file */

    int policysize = 0;
    char *policylang = args->policylang;

    if (args->policyfile) {
      policy = readfromfile(args->policyfile, &policysize, warning);

      if (!policy) {
        setAdditional(additional, args->policyfile);
        goto err;
      }
    }
    
    /* setting policy language field */
    
    if (!policylang) {
      if (!args->policyfile) {
        policylang = IMPERSONATION_PROXY_OID;
        setWarning(warning, PROXY_WARNING_GSI_ASSUMED);
      }
      else {
        policylang = GLOBUS_GSI_PROXY_GENERIC_POLICY_OID;
        setWarning(warning, PROXY_WARNING_GENERIC_LANGUAGE_ASSUMED);
      }
    }
    
    /* predefined policy language can be specified with simple name string */
    
    else if (strcmp(policylang, IMPERSONATION_PROXY_SN) == 0)
      policylang = IMPERSONATION_PROXY_OID;
    else if (strcmp(policylang, INDEPENDENT_PROXY_SN) == 0)
      policylang = INDEPENDENT_PROXY_OID;
    
    /* does limited prevail on others? don't know what does grid-proxy_init since if pl is given with
       limited options it crash */
    if (args->limited)
      policylang = LIMITED_PROXY_OID;

    OBJ_create(policylang, policylang, policylang);
    
    if (!(policy_language = OBJ_nid2obj(OBJ_sn2nid(policylang)))) {
      PRXYerr(PRXYERR_F_PROXY_SIGN, PRXYERR_R_CLASS_ADD_OID);
      goto err;
    }
    
    int nativeopenssl = proxynative();

    if (args->proxyversion == 3 || (args->proxyversion == 4 && !nativeopenssl)) {
      /* proxypolicy */
    
      proxypolicy = myPROXYPOLICY_new();

      if (policy) {
        myPROXYPOLICY_set_policy(proxypolicy, (unsigned char*)policy, policysize);
        free(policy);
        policy = NULL;
      }
      else if (args->policytext)
        myPROXYPOLICY_set_policy(proxypolicy, 
                                 (unsigned char*)args->policytext, 
                                 strlen(args->policytext));

      myPROXYPOLICY_set_policy_language(proxypolicy, policy_language);

      /* proxycertinfo */
    
      proxycertinfo = myPROXYCERTINFO_new();
      myPROXYCERTINFO_set_version(proxycertinfo, args->proxyversion);
      myPROXYCERTINFO_set_proxypolicy(proxycertinfo, proxypolicy);

      myPROXYPOLICY_free(proxypolicy);

      if (args->pathlength>=0)
        myPROXYCERTINFO_set_path_length(proxycertinfo, args->pathlength);

      value = (char *)proxycertinfo;
    }
    else {
      if (args->pathlength != -1) {
        char *buffer = snprintf_wrap("%d", args->pathlength);

        if (policy) {
          value = snprintf_wrap("language:%s,pathlen:%s,policy:text:%s", policylang, buffer, policy);
          free(policy);
          policy = NULL;
        }
        else if (args->policytext)
          value = snprintf_wrap("language:%s,pathlen:%s,policy:text:%s", policylang, buffer, args->policytext);
        else
          value = snprintf_wrap("language:%s,pathlen:%s", policylang, buffer);
        free(buffer);
      }
      else {
        if (policy)
          value = snprintf_wrap("language:%s,policy:text:%s", policylang, policy);
        else if (args->policytext)
          value = snprintf_wrap("language:%s,policy:text:%s", policylang, args->policytext);
        else
          value = snprintf_wrap("language:%s", policylang);
      }
    }

    if (args->proxyversion == 3) {
      ex7 = X509V3_EXT_conf_nid(NULL, NULL, my_txt2nid(PROXYCERTINFO_V3), (char*)proxycertinfo);
      value = NULL;
    } else {
      if (nativeopenssl) {
        X509V3_CTX ctx;
        X509V3_set_ctx(&ctx, NULL, NULL, NULL, NULL, 0L);
        ctx.db = (void*)&ctx;
        X509V3_CONF_METHOD method = { NULL, NULL, NULL, NULL };
        ctx.db_meth = &method;
        ex7 = X509V3_EXT_conf_nid(NULL, &ctx, my_txt2nid(PROXYCERTINFO_V4), (char*)value);
        free(value);
        value = NULL;
      }
      else
        ex7 = X509V3_EXT_conf_nid(NULL, NULL, my_txt2nid(PROXYCERTINFO_V4), (char*)value);
      value = NULL;
    }

    if (policy) {
      free(policy);
      policy = NULL;
    }

    if (ex7 == NULL) {
      PRXYerr(PRXYERR_F_PROXY_SIGN, PRXYERR_R_CLASS_ADD_EXT);
      goto err;
    }

    if (args->proxyversion == 4) {
      X509_EXTENSION_set_critical(ex7, 1);
    }

    if (!SET_EXT(ex7))
      goto err;
  }
  
  if (!args->selfsigned)  {
    if (proxy_sign(args->cert,
                   args->key,
                   req,
                   &ncert,
                   args->hours*60*60 + args->minutes*60,
                   extensions,
                   args->limited,
                   args->proxyversion,
                   args->newsubject,
                   args->newissuer,
                   args->pastproxy,
                   args->newserial,
                   args->selfsigned)) {
      goto err;
    }
  }
  else  {
    if (proxy_sign(NULL,
                   npkey,
                   req,
                   &ncert,
                   args->hours*60*60 + args->minutes*60,
                   extensions,
                   args->limited,
                   0,
                   args->newsubject,
                   args->newsubject,
                   args->pastproxy,
                   NULL,
                   args->selfsigned)) {
      goto err;
    }
  }

  proxy = (struct VOMSProxy*)malloc(sizeof(struct VOMSProxy));

  if (proxy) {
    proxy->cert = ncert;
    proxy->key = npkey;
    proxy->chain = sk_X509_new_null();

    if (args->cert)
      sk_X509_push(proxy->chain, X509_dup(args->cert));

    for (i = 0; i < sk_X509_num(args->chain); i++)
      sk_X509_push(proxy->chain, X509_dup(sk_X509_value(args->chain, i)));
  }

 err:

  if (!proxy) {
    X509_free(ncert);
    EVP_PKEY_free(npkey);
  }

  if (extensions) {
    sk_X509_EXTENSION_pop_free(extensions, X509_EXTENSION_free);
  }
  if (!args->proxyrequest)
    X509_REQ_free(req);

  X509_EXTENSION_free(ex13);
  X509_EXTENSION_free(ex12);
  X509_EXTENSION_free(ex11);
  X509_EXTENSION_free(ex10);
  X509_EXTENSION_free(ex9);
  X509_EXTENSION_free(ex8);
  X509_EXTENSION_free(ex6);
  X509_EXTENSION_free(ex7);
  X509_EXTENSION_free(ex5);
  X509_EXTENSION_free(ex2);
  X509_EXTENSION_free(ex3);
  X509_EXTENSION_free(ex4);
  X509_EXTENSION_free(ex1);
  free(policy);
  free(value);
  return proxy;
}

X509_EXTENSION *CreateProxyExtension(char * name, char *data, int datalen, int crit) 
{

  X509_EXTENSION *                    ex = NULL;
  ASN1_OBJECT *                       ex_obj = NULL;
  ASN1_OCTET_STRING *                 ex_oct = NULL;

  int nid = OBJ_txt2nid(name);

  if (nid != 0)
    ex_obj = OBJ_nid2obj(nid);
  else
    ex_obj = OBJ_txt2obj(name, 0);
                 
  if (!ex_obj) {
    PRXYerr(PRXYERR_F_PROXY_SIGN,PRXYERR_R_CLASS_ADD_OID);
    goto err;
  }
  
  if (!(ex_oct = ASN1_OCTET_STRING_new())) {
    PRXYerr(PRXYERR_F_PROXY_SIGN,PRXYERR_R_CLASS_ADD_EXT);
    goto err;
  }
  
  ex_oct->data   = (unsigned char*)data;
  ex_oct->length = datalen;
  
  if (!(ex = X509_EXTENSION_create_by_OBJ(NULL, ex_obj, crit, ex_oct))) {
    PRXYerr(PRXYERR_F_PROXY_SIGN,PRXYERR_R_CLASS_ADD_EXT);
  }
	
 err:
  
  if (ex_oct) {
    /* avoid spurious free of the contents. */
    ex_oct->length = 0;
    ex_oct->data = NULL;
    ASN1_OCTET_STRING_free(ex_oct);
  }

  ASN1_OBJECT_free(ex_obj);
  
  return ex;
  
}


static char *readfromfile(char *file, int *size, int *warning)
{
  int fd = open(file,O_RDONLY);
  char *buffer = NULL;

  if (fd != -1) {
    struct stat filestats;

    if (!fstat(fd, &filestats)) {
      *size = filestats.st_size;

      buffer = (char *)malloc(*size);

      if (buffer) {
        int offset = 0;
        int ret = 0;

        do {
          ret = read(fd, buffer+offset, *size - offset);
          offset += ret;
        } while ( ret > 0);

        if (ret < 0) {
          free(buffer);
          buffer = NULL;
          setWarning(warning, PROXY_ERROR_FILE_READ);
        }
      }
      else
        setWarning(warning, PROXY_ERROR_OUT_OF_MEMORY);
    }
    else
      setWarning(warning, PROXY_ERROR_STAT_FILE);
    close(fd);
  }
  else
    setWarning(warning, PROXY_ERROR_OPEN_FILE);


  return buffer;
}

static void setWarning(int *warning, int value)
{
  if (warning)
    *warning = value;
}

static void setAdditional(void **additional, void *data)
{
  if (additional)
    *additional = data;
}

static X509_EXTENSION *set_KeyUsageFlags(int flags)
{
  unsigned char data[2];

  X509_EXTENSION  *ext = NULL;
  ASN1_BIT_STRING *str = ASN1_BIT_STRING_new();
  
  if (str) {
    int len =0;

    data[0] =  flags & 0x00ff;
    data[1] = (flags & 0xff00) >> 8;

    len = (data[1] ? 2 : 1);

    ASN1_BIT_STRING_set(str, data, len);

    ext = X509V3_EXT_i2d(NID_key_usage, 1, str);
    ASN1_BIT_STRING_free(str);

    return ext;
  }

  return NULL;
}

static X509_EXTENSION *set_ExtendedKeyUsageFlags(char *flagnames)
{
  if (!flagnames)
    return NULL;

  return X509V3_EXT_conf_nid(NULL, NULL, NID_ext_key_usage, flagnames);
}

static X509_EXTENSION *get_BasicConstraints(int ca) 
{
  return X509V3_EXT_conf_nid(NULL, NULL, NID_basic_constraints, (ca ? "CA:true" : "CA:false"));
}

static int get_KeyUsageFlags(X509 *cert)
{
  int keyusage = 0;

  ASN1_BIT_STRING *usage = X509_get_ext_d2i(cert, NID_key_usage, NULL, NULL);
  
  if (usage) {
    if (usage->length > 0)
      keyusage = usage->data[0];
    if (usage->length > 1)
      keyusage |= usage->data[1] << 8;

    ASN1_BIT_STRING_free(usage);
  }

  return keyusage;
}

static char *getBitName(char**string)
{
  char *div = NULL; 
  char *temp = NULL;

  if (!string || !(*string) || (*(*string) == '\0'))
    return NULL;

  div = strchr(*string, ',');

  if (div) {
    temp = *string;
    *div++ = '\0';
    *string = div;
  }
  else {
    temp = *string;
    *string = *string + strlen(*string);
  }

  return temp;
}

static int getBitValue(char *bitname)
{
  if (!strcmp(bitname, "digitalSignature"))
    return KU_DIGITAL_SIGNATURE;
  else if (!strcmp(bitname, "nonRepudiation"))
    return KU_NON_REPUDIATION;
  else if (!strcmp(bitname, "keyEncipherment"))
    return KU_KEY_ENCIPHERMENT;
  else if (!strcmp(bitname, "dataEncipherment"))
    return KU_DATA_ENCIPHERMENT;
  else if (!strcmp(bitname, "keyAgreement"))
    return KU_KEY_AGREEMENT;
  else if (!strcmp(bitname, "keyCertSign"))
    return KU_KEY_CERT_SIGN;
  else if (!strcmp(bitname, "cRLSign"))
    return KU_CRL_SIGN;
  else if (!strcmp(bitname, "encipherOnly"))
    return KU_ENCIPHER_ONLY;
  else if (!strcmp(bitname, "decipherOnly"))
    return KU_DECIPHER_ONLY;

  return 0;
}


static int convertMethod(char *bits, int *warning, void **additional)
{
  char *bitname = NULL;
  int value = 0;
  int total = 0;

  while ((bitname = getBitName(&bits))) {
    value = getBitValue(bitname);
    if (value == 0) {
      setWarning(warning, PROXY_ERROR_UNKNOWN_BIT);
      setAdditional(additional, bitname);
      return -1;
    }
    total |= value;
  }

  return total;
}

char *ProxyCreationError(int error, void *additional)
{
  switch (error) {
  case PROXY_NO_ERROR:
    return NULL;
    break;

  case PROXY_ERROR_OPEN_FILE:
    return snprintf_wrap("Error: cannot open file: %s\n%s\n", additional, strerror(errno));
    break;

  case PROXY_ERROR_FILE_READ:
    return snprintf_wrap("Error: cannot read from file: %s\n%s\n", additional, strerror(errno));
    break;

  case PROXY_ERROR_STAT_FILE:
    return snprintf_wrap("Error: cannot stat file: %s\n%s\n", additional, strerror(errno));
    break;

  case PROXY_ERROR_OUT_OF_MEMORY:
    return snprintf_wrap("Error: out of memory");
    break;

  case PROXY_ERROR_UNKNOWN_BIT:
    return snprintf_wrap("KeyUsage bit: %s unknown\n", additional);
    break;

  case PROXY_ERROR_UNKNOWN_EXTENDED_BIT:
    return snprintf_wrap("ExtKeyUsage bit value: %s invalid.  One or more of the bits are unknown\n", additional);
    break;

  case PROXY_WARNING_GSI_ASSUMED:
    return snprintf_wrap("\nNo policy language specified, Gsi impersonation proxy assumed.");
    break;

  case PROXY_WARNING_GENERIC_LANGUAGE_ASSUMED:
    return snprintf_wrap("\nNo policy language specified with policy file, assuming generic.");
    break;

  default:
    return snprintf_wrap("Unknown error");
    break;
  }
}
