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

static X509_EXTENSION *CreateProxyExtension(char * name, char *data, int datalen, int crit);
static char *readfromfile(char *file, int *size, int *warning);
static void setWarning(int *warning, int value);
static void setAdditional(void **additional, void *data);
static X509_EXTENSION *set_KeyUsageFlags(int flags);
static int get_KeyUsageFlags(X509 *cert);
static X509_EXTENSION *set_ExtendedKeyUsageFlags(char *flagnames);
static char *getBitName(char**string);
static int getBitValue(char *bitname, int *bittype);
static int convertMethod(char *bits, int type);

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

struct VOMSProxy *VOMS_MakeProxy(struct VOMSProxyArguments *args, int *warning, void **additional) 
{
  char *confstr = NULL;
  char *value = NULL;

  X509 * ncert = NULL;
  EVP_PKEY * npkey = NULL;
  X509_REQ * req = NULL;
  STACK_OF(X509_EXTENSION) * extensions = NULL;
  int ku_flags = 0;

  X509_EXTENSION *ex1 = NULL, *ex2 = NULL, *ex3 = NULL, 
    *ex4 = NULL, *ex5 = NULL, *ex6 = NULL, *ex7 = NULL, 
    *ex8 = NULL, *ex9 = NULL, *ex10 = NULL, *ex11 = NULL;

  int voms = 0, classadd = 0, file = 0, vo = 0, acs = 0, info = 0, 
    kusg = 0, order = 0, extku = 0, nscert = 0, akey = 0;
  int i = 0;
  int proxyindex;
  
  struct VOMSProxy *proxy = NULL;

  static int init = 0;

  AUTHORITY_KEYID *akeyid = NULL;
  ASN1_OCTET_STRING *ikeyid = NULL;

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

  /* Add passed extensions */
  if (args->extensions) {
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

  /* initialize extensions stack */

  if ((extensions = sk_X509_EXTENSION_new_null()) == NULL) {
    PRXYerr(PRXYERR_F_PROXY_SIGN, PRXYERR_R_CLASS_ADD_EXT);
    goto err;
  }

  /* voms extension */
  
  if (args->datalen) {
    if ((ex1 = CreateProxyExtension("voms", args->data, args->datalen, 0)) == NULL) {
      PRXYerr(PRXYERR_F_PROXY_SIGN, PRXYERR_R_CLASS_ADD_EXT);
      goto err;
    }

    if (!sk_X509_EXTENSION_push(extensions, ex1)) {
      PRXYerr(PRXYERR_F_PROXY_SIGN, PRXYERR_R_CLASS_ADD_EXT);
      goto err;
    }

    voms = 1;
  }

  /* include extension */

  if (args->filename) {

    int filesize;
    char *filedata = readfromfile(args->filename, &filesize, warning);

    if (filedata) {
      if ((ex3 = CreateProxyExtension("incfile", filedata, filesize, 0)) == NULL) {
        PRXYerr(PRXYERR_F_PROXY_SIGN, PRXYERR_R_CLASS_ADD_EXT);
        goto err;
      }

      if (!sk_X509_EXTENSION_push(extensions, ex3)) {
        PRXYerr(PRXYERR_F_PROXY_SIGN, PRXYERR_R_CLASS_ADD_EXT);
        goto err;
      }

      file = 1;
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
    
    if (!sk_X509_EXTENSION_push(extensions, ex5)) {
      PRXYerr(PRXYERR_F_PROXY_SIGN, PRXYERR_R_CLASS_ADD_EXT);
      goto err;
    }
    
    acs = 1;
  }

  /* keyUsage extension */

  if (!args->keyusage) {
    ku_flags = get_KeyUsageFlags(args->cert);
    ku_flags &= ~X509v3_KU_KEY_CERT_SIGN;
    ku_flags &= ~X509v3_KU_NON_REPUDIATION;
  }
  else {
    ku_flags = convertMethod(args->keyusage, EXFLAG_KUSAGE);
    if (ku_flags == -1) {
      PRXYerr(PRXYERR_F_PROXY_SIGN, PRXYERR_R_CLASS_ADD_EXT);
      goto err;
    }
  }

  if ((ex8 = set_KeyUsageFlags(ku_flags)) == NULL) {
    PRXYerr(PRXYERR_F_PROXY_SIGN, PRXYERR_R_CLASS_ADD_EXT);
    goto err;
  }

  X509_EXTENSION_set_critical(ex8, 1);

  if (!sk_X509_EXTENSION_push(extensions, ex8)) {
    PRXYerr(PRXYERR_F_PROXY_SIGN,PRXYERR_R_CLASS_ADD_EXT);
    goto err;
  }

  kusg = 1;

  /* netscapeCert extension */
  if (args->netscape) {

    if ((ex9 = X509V3_EXT_conf_nid(NULL, NULL, NID_netscape_cert_type, args->netscape)) == NULL) {
      //      PRXYerr(PRXYERR_F_PROXY_SIGN, PRXYERR_R_CLASS_ADD_EXT);
      goto err;
    }

    if (!sk_X509_EXTENSION_push(extensions, ex9)) {
      PRXYerr(PRXYERR_F_PROXY_SIGN,PRXYERR_R_CLASS_ADD_EXT);
      goto err;
    }

    nscert = 1;
  }

  /* extended key usage */

  if (args->exkusage) {
    if ((ex10 = set_ExtendedKeyUsageFlags(args->exkusage)) == NULL) {
      PRXYerr(PRXYERR_F_PROXY_SIGN, PRXYERR_R_CLASS_ADD_EXT);
      goto err;
    }

    if (!sk_X509_EXTENSION_push(extensions, ex10)) {
      PRXYerr(PRXYERR_F_PROXY_SIGN,PRXYERR_R_CLASS_ADD_EXT);
      goto err;
    }

    extku = 1;
  }

  /* vo extension */
  
  if (!args->voID) {
    if ((ex4 = CreateProxyExtension("vo", args->voID, strlen(args->voID), 0)) == NULL) {
      PRXYerr(PRXYERR_F_PROXY_SIGN,PRXYERR_R_CLASS_ADD_EXT);
      goto err;
    }
    
    if (!sk_X509_EXTENSION_push(extensions, ex4)) {
      PRXYerr(PRXYERR_F_PROXY_SIGN,PRXYERR_R_CLASS_ADD_EXT);
      goto err;
    }
    
    vo = 1;
  }
  
  /* authority key identifier extension */

  {
    X509V3_CTX ctx;
    
    X509V3_set_ctx(&ctx, args->cert, NULL, NULL, NULL, 0);
          
    ex11 = X509V3_EXT_conf_nid(NULL, &ctx, NID_authority_key_identifier, "keyid");

    if (!ex11) {
      PRXYerr(PRXYERR_F_PROXY_SIGN,PRXYERR_R_CLASS_ADD_EXT);
      goto err;
    }
          
    if (!sk_X509_EXTENSION_push(extensions, ex11)) {
      PRXYerr(PRXYERR_F_PROXY_SIGN,PRXYERR_R_CLASS_ADD_EXT);
      goto err;
    }

    akey = 1;
  }


  /* class_add extension */

#ifdef CLASS_ADD
  
  if (class_add_buf && class_add_buf_len > 0) {
    if ((ex2 = proxy_extension_class_add_create((void *)args->class_add_buf, args->class_add_buf_len)) == NULL) {
      PRXYerr(PRXYERR_F_PROXY_SIGN,PRXYERR_R_CLASS_ADD_EXT);
      goto err;
    }
    
    if (!sk_X509_EXTENSION_push(extensions, ex2)) {
      PRXYerr(PRXYERR_F_PROXY_SIGN,PRXYERR_R_CLASS_ADD_EXT);
      goto err;
    }
    
    classadd = 1;
  }

#endif
  /* order extension */
 
#if 0
  if (args->aclist && dataorder) {
    char *buffer = BN_bn2hex(dataorder);

    if ((ex6 = CreateProxyExtension("order", buffer, strlen(buffer), 0)) == NULL) {
      PRXYerr(PRXYERR_F_PROXY_SIGN,PRXYERR_R_CLASS_ADD_EXT);
      goto err;
    }

    if (!sk_X509_EXTENSION_push(extensions, ex6)) {
      PRXYerr(PRXYERR_F_PROXY_SIGN,PRXYERR_R_CLASS_ADD_EXT);
      goto err;
    }

    order = 1;
  }
#endif

  /* PCI extension */
  
  if (args->proxyversion>=3) {
    myPROXYPOLICY *                     proxypolicy;
    myPROXYCERTINFO *                   proxycertinfo = NULL;
    ASN1_OBJECT *                       policy_language;

    /* getting contents of policy file */

    char *policy = NULL;
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

      if (args->pathlength>=0)
        myPROXYCERTINFO_set_path_length(proxycertinfo, args->pathlength);

      value = (char *)proxycertinfo;
    }
    else {
      if (policysize == 0)
        if (args->policytext)
          policysize = strlen(args->policytext);

      value = (char*)calloc(1, policysize + strlen(policylang) + 
                            31 + 1 + 30);

      if (args->pathlength != -1) {
        char buffer[31];
      
        snprintf(buffer, 30, "%d", args->pathlength);
        buffer[30]='\0';
        if (!args->policytext) {
          sprintf(value, "language:%s,pathlen:%s,policy:text:%s", policylang, buffer, policy);
          free(policy);
        }
        else 
          sprintf(value, "language:%s,pathlen:%s,policy:text:%s", policylang, buffer, args->policytext);
      }
      else
        if (!args->policytext)
          sprintf(value, "language:%s,policy:text:%s", policylang, policy);
        else
          sprintf(value, "language:%s,policy:text:%s", policylang, args->policytext);
    }

    if (args->proxyversion == 3) {
      ex7 = X509V3_EXT_conf_nid(NULL, NULL, OBJ_obj2nid(OBJ_txt2obj(PROXYCERTINFO_V3,1)), (char*)proxycertinfo);
      value = NULL;
    } else {
      if (nativeopenssl) {
        X509V3_CTX ctx;
        X509V3_set_ctx(&ctx, NULL, NULL, NULL, NULL, 0L);
        ctx.db = (void*)&ctx;
        ex7 = X509V3_EXT_conf_nid(NULL, &ctx, OBJ_obj2nid(OBJ_txt2obj(PROXYCERTINFO_V4,1)), (char*)value);
        free(value);
        value = NULL;
      }
      else
        ex7 = X509V3_EXT_conf_nid(NULL, NULL, OBJ_obj2nid(OBJ_txt2obj(PROXYCERTINFO_V4,1)), (char*)value);
      value = NULL;
    }

    if (ex7 == NULL) {
      PRXYerr(PRXYERR_F_PROXY_SIGN, PRXYERR_R_CLASS_ADD_EXT);
      goto err;
    }

    if (args->proxyversion == 4) {
      X509_EXTENSION_set_critical(ex7, 1);
    }

    if (!sk_X509_EXTENSION_push(extensions, ex7)) {
      PRXYerr(PRXYERR_F_PROXY_SIGN,PRXYERR_R_CLASS_ADD_EXT);
      goto err;
    }
  }
  
  if (proxy_sign(args->cert,
                 args->key,
                 req,
                 &ncert,
                 args->hours*60*60 + args->minutes*60,
                 extensions,
                 args->limited,
                 args->proxyversion,
                 args->newsubject ? args->newsubject : NULL,
                 args->newissuer,
                 args->pastproxy,
                 args->newserial)) {
    goto err;
  }
  

  proxy = (struct VOMSProxy*)malloc(sizeof(struct VOMSProxy));

  if (proxy) {
    proxy->cert = ncert;
    proxy->key = npkey;
    proxy->chain = sk_X509_new_null();

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
    akey = extku = nscert = order = kusg = voms = classadd = file = vo = acs = info = 0;
  }
  if (!args->proxyrequest)
    X509_REQ_free(req);

  if (akey)
    X509_EXTENSION_free(ex11);
  if (extku)
    X509_EXTENSION_free(ex10);
  if (nscert)
    X509_EXTENSION_free(ex9);
  if (kusg)
    X509_EXTENSION_free(ex8);
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

  free(value);
  return proxy;

}

static X509_EXTENSION *CreateProxyExtension(char * name, char *data, int datalen, int crit) 
{

  X509_EXTENSION *                    ex = NULL;
  ASN1_OBJECT *                       ex_obj = NULL;
  ASN1_OCTET_STRING *                 ex_oct = NULL;

  if (!(ex_obj = OBJ_nid2obj(OBJ_txt2nid(name)))) {
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
    goto err;
  }
	
  return ex;
  
 err:
  
  ASN1_OCTET_STRING_free(ex_oct);
  ASN1_OBJECT_free(ex_obj);
  
  return NULL;
  
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
  int len =0;
  unsigned char data[2];

  X509_EXTENSION  *ext = NULL;
  ASN1_BIT_STRING *str = ASN1_BIT_STRING_new();
  
  if (str) {
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

static int getBitValue(char *bitname, int *bittype)
{

  *bittype = EXFLAG_KUSAGE;
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

  *bittype = EXFLAG_NSCERT;

  if (!strcmp(bitname, "client"))
    return NS_SSL_CLIENT;
  else if (!strcmp(bitname, "server"))
    return NS_SSL_SERVER;
  else if (!strcmp(bitname, "email"))
    return NS_SMIME;
  else if (!strcmp(bitname, "objsign"))
    return NS_OBJSIGN;
  else if (!strcmp(bitname, "sslCA"))
    return NS_SSL_CA;
  else if (!strcmp(bitname, "emailCA"))
    return NS_SMIME_CA;
  else if (!strcmp(bitname, "objCA"))
    return NS_OBJSIGN_CA;

  *bittype = EXFLAG_XKUSAGE;

  return 0;
}


static int convertMethod(char *bits, int type)
{
  char *bitname = NULL;
  int realtype = 0;
  int value = 0;
  int total = 0;

  while (bitname = getBitName(&bits)) {
    value = getBitValue(bitname, &realtype);
    if (value == 0 || type != realtype)
      return -1;
    total |= value;
  }

  return total;
}
