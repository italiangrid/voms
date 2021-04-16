/*********************************************************************
 *
 * Authors: Valerio Venturi - Valerio.Venturi@cnaf.infn.it
 *          Vincenzo Ciaschini - Vincenzo.Ciaschini@cnaf.infn.it
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

#include <stdio.h>

#include <openssl/err.h>
#include <openssl/asn1.h>
#include <openssl/objects.h>

#include "myproxycertinfo.h"
#include "doio.h"

/* myPROXYPOLICY function */

myPROXYPOLICY * myPROXYPOLICY_new() 
{
  myPROXYPOLICY* ret = (myPROXYPOLICY*)OPENSSL_malloc(sizeof(myPROXYPOLICY));

  if (ret)
  {
    ret->policy_language = OBJ_nid2obj(OBJ_sn2nid(IMPERSONATION_PROXY_SN));
    ret->policy = NULL;
  }

  return ret;
}

void myPROXYPOLICY_free(myPROXYPOLICY * policy) 
{
  if(policy == NULL) return;

  ASN1_OBJECT_free(policy->policy_language);
  ASN1_OCTET_STRING_free(policy->policy);
  OPENSSL_free(policy);
}

/* duplicate */
myPROXYPOLICY * myPROXYPOLICY_dup(myPROXYPOLICY * policy) 
{
#ifdef TYPEDEF_I2D_OF
  return ((myPROXYPOLICY *) ASN1_dup((i2d_of_void *)i2d_myPROXYPOLICY,
				   (d2i_of_void *)d2i_myPROXYPOLICY,
				   (char *)policy));
#else
  return ((myPROXYPOLICY *) ASN1_dup((int (*)())i2d_myPROXYPOLICY,
				   (char *(*)())d2i_myPROXYPOLICY,
				   (char *)policy));
#endif
}

/* set policy language */
int myPROXYPOLICY_set_policy_language(myPROXYPOLICY * policy, ASN1_OBJECT * policy_language) 
{
  if(policy_language != NULL) {
    ASN1_OBJECT_free(policy->policy_language);
    policy->policy_language = OBJ_dup(policy_language);
    return 1;
  }

  return 0;
}

/* get policy language */
ASN1_OBJECT * myPROXYPOLICY_get_policy_language(myPROXYPOLICY * policy)
{
    return policy->policy_language;
}

/* set policy */
int myPROXYPOLICY_set_policy(myPROXYPOLICY * proxypolicy, unsigned char * policy, int length) 
{
  if(policy != NULL) {
    /* if member policy of proxypolicy non set */
    if(!proxypolicy->policy)
      proxypolicy->policy = ASN1_OCTET_STRING_new();
      
    /* set member policy of proxypolicy */
    ASN1_OCTET_STRING_set(proxypolicy->policy, policy, length);
  }
  else 
    ASN1_OCTET_STRING_free(proxypolicy->policy);

  return 1;
}

/* get policy */
unsigned char * myPROXYPOLICY_get_policy(myPROXYPOLICY * proxypolicy, int * length) 
{
  /* assure field policy is set */

  if(proxypolicy->policy) {
    *length = proxypolicy->policy->length;

    /* assure ASN1_OCTET_STRING is full */
    if (*length>0 && proxypolicy->policy->data) {
      unsigned char * copy = malloc(*length);
      memcpy(copy, proxypolicy->policy->data, *length);
      return copy;
    }
  }
  return NULL;
}

/* internal to der conversion */
int i2d_myPROXYPOLICY(myPROXYPOLICY * policy, unsigned char ** pp) 
{
  M_ASN1_I2D_vars(policy);

  M_ASN1_I2D_len(policy->policy_language, i2d_ASN1_OBJECT);

  if(policy->policy) { 
    M_ASN1_I2D_len(policy->policy, i2d_ASN1_OCTET_STRING);
  }
    
  M_ASN1_I2D_seq_total();
  M_ASN1_I2D_put(policy->policy_language, i2d_ASN1_OBJECT);

  if(policy->policy) { 
    M_ASN1_I2D_put(policy->policy, i2d_ASN1_OCTET_STRING);
  }

  M_ASN1_I2D_finish();
}

myPROXYPOLICY * d2i_myPROXYPOLICY(myPROXYPOLICY ** a, unsigned char ** pp, long length)
{
    M_ASN1_D2I_vars(a, myPROXYPOLICY *, myPROXYPOLICY_new);
    
    M_ASN1_D2I_Init();
    M_ASN1_D2I_start_sequence();
    M_ASN1_D2I_get(ret->policy_language, d2i_ASN1_OBJECT);

    /* need to try getting the policy using
     *     a) a call expecting no tags
     *     b) a call expecting tags
     * one of which should succeed
     */
    
    M_ASN1_D2I_get_opt(ret->policy,
                       d2i_ASN1_OCTET_STRING,
                       V_ASN1_OCTET_STRING);
    M_ASN1_D2I_get_IMP_opt(ret->policy,
                           d2i_ASN1_OCTET_STRING,
                           0,
                           V_ASN1_OCTET_STRING);
    M_ASN1_D2I_Finish(a, 
                      myPROXYPOLICY_free, 
                      ASN1_F_D2I_PROXYPOLICY);
}



/* myPROXYCERTINFO function */

myPROXYCERTINFO * myPROXYCERTINFO_new() 
{
  myPROXYCERTINFO *                   ret = NULL;
  ASN1_CTX                            c;

  M_ASN1_New_Malloc(ret, myPROXYCERTINFO);
  memset(ret, 0, sizeof(myPROXYCERTINFO));
  ret->path_length      = NULL;
  ret->proxypolicy           = myPROXYPOLICY_new();
  return (ret);
  M_ASN1_New_Error(ASN1_F_PROXYCERTINFO_NEW);
}

void myPROXYCERTINFO_free(myPROXYCERTINFO * proxycertinfo) 
{ 
  /* assure proxycertinfo not empty */ 
  if(proxycertinfo == NULL) return;
  
  ASN1_INTEGER_free(proxycertinfo->path_length);
  myPROXYPOLICY_free(proxycertinfo->proxypolicy);
  OPENSSL_free(proxycertinfo);
}

/* set path_length */
int myPROXYCERTINFO_set_path_length(myPROXYCERTINFO * proxycertinfo, long path_length) 
{  
  /* assure proxycertinfo is not empty */
  if(proxycertinfo != NULL) {

    if(path_length != -1) {
      /* if member path_length is empty allocate memory then set */
      if(proxycertinfo->path_length == NULL)
	proxycertinfo->path_length = ASN1_INTEGER_new();
      return ASN1_INTEGER_set(proxycertinfo->path_length, path_length);
    }
    else {
      ASN1_INTEGER_free(proxycertinfo->path_length);
      proxycertinfo->path_length = NULL;
    }

    return 1;
  }

  return 0;
}

int myPROXYCERTINFO_set_version(myPROXYCERTINFO * proxycertinfo, int version)
{
  if (proxycertinfo != NULL) {
    proxycertinfo->version = version;
    return 1;
  }

  return 0;
}

int myPROXYCERTINFO_get_version(myPROXYCERTINFO * proxycertinfo)
{
  if (proxycertinfo)
    return proxycertinfo->version;
  return -1;
}


/* get path length */
long myPROXYCERTINFO_get_path_length(myPROXYCERTINFO * proxycertinfo) 
{
  if(proxycertinfo && proxycertinfo->path_length)
    return ASN1_INTEGER_get(proxycertinfo->path_length);
  else 
    return -1;
}

/* set policy */
int myPROXYCERTINFO_set_proxypolicy(myPROXYCERTINFO * proxycertinfo, myPROXYPOLICY * proxypolicy) 
{
  myPROXYPOLICY_free(proxycertinfo->proxypolicy);

  if(proxypolicy != NULL)
    proxycertinfo->proxypolicy = myPROXYPOLICY_dup(proxypolicy);
  else
    proxycertinfo->proxypolicy = NULL;

  return 1;
}

/* get policy */
myPROXYPOLICY * myPROXYCERTINFO_get_proxypolicy(myPROXYCERTINFO * proxycertinfo) 
{
  if(proxycertinfo)
    return proxycertinfo->proxypolicy;

  return NULL;
}

/* internal to der conversion */
static int i2d_myPROXYCERTINFO_v3(myPROXYCERTINFO * proxycertinfo, unsigned char ** pp) 
{
    int                                 v1;

    M_ASN1_I2D_vars(proxycertinfo);
    
    v1 = 0;

    M_ASN1_I2D_len(proxycertinfo->proxypolicy, i2d_myPROXYPOLICY);

    M_ASN1_I2D_len_EXP_opt(proxycertinfo->path_length,i2d_ASN1_INTEGER, 1, v1);
    M_ASN1_I2D_seq_total();
    M_ASN1_I2D_put(proxycertinfo->proxypolicy, i2d_myPROXYPOLICY);
    M_ASN1_I2D_put_EXP_opt(proxycertinfo->path_length, i2d_ASN1_INTEGER, 1, v1);
    M_ASN1_I2D_finish();
}

static int i2d_myPROXYCERTINFO_v4(myPROXYCERTINFO * proxycertinfo, unsigned char ** pp) 
{
    M_ASN1_I2D_vars(proxycertinfo);

    if(proxycertinfo->path_length)
    { 
        M_ASN1_I2D_len(proxycertinfo->path_length, i2d_ASN1_INTEGER);
    }
    
    M_ASN1_I2D_len(proxycertinfo->proxypolicy, i2d_myPROXYPOLICY);

    M_ASN1_I2D_seq_total();
    if(proxycertinfo->path_length)
    { 
        M_ASN1_I2D_put(proxycertinfo->path_length, i2d_ASN1_INTEGER);
    }
    M_ASN1_I2D_put(proxycertinfo->proxypolicy, i2d_myPROXYPOLICY);
    M_ASN1_I2D_finish();
}

int i2d_myPROXYCERTINFO(myPROXYCERTINFO * proxycertinfo, unsigned char ** pp) 
{
  switch(proxycertinfo->version) {
  case 3:
    return i2d_myPROXYCERTINFO_v3(proxycertinfo, pp);
    break;

  case 4:
    return i2d_myPROXYCERTINFO_v4(proxycertinfo, pp);
    break;

  default:
    return -1;
    break;
  }
}

static myPROXYCERTINFO * d2i_myPROXYCERTINFO_v3(myPROXYCERTINFO ** cert_info, unsigned char ** pp, long length)
{
    M_ASN1_D2I_vars(cert_info, myPROXYCERTINFO *, myPROXYCERTINFO_new);

    M_ASN1_D2I_Init();
    M_ASN1_D2I_start_sequence();

    M_ASN1_D2I_get((ret->proxypolicy), d2i_myPROXYPOLICY);

    M_ASN1_D2I_get_EXP_opt(ret->path_length, d2i_ASN1_INTEGER, 1);

    ret->version = 3;
    M_ASN1_D2I_Finish(cert_info, myPROXYCERTINFO_free, ASN1_F_D2I_PROXYCERTINFO);
}

static myPROXYCERTINFO * d2i_myPROXYCERTINFO_v4(myPROXYCERTINFO ** cert_info, unsigned char ** pp, long length)
{
    M_ASN1_D2I_vars(cert_info, myPROXYCERTINFO *, myPROXYCERTINFO_new);

    M_ASN1_D2I_Init();
    M_ASN1_D2I_start_sequence();

    M_ASN1_D2I_get_EXP_opt(ret->path_length, d2i_ASN1_INTEGER, 1);
    
    M_ASN1_D2I_get_opt(ret->path_length, d2i_ASN1_INTEGER, V_ASN1_INTEGER);

    M_ASN1_D2I_get((ret->proxypolicy),d2i_myPROXYPOLICY);

    ret->version = 4;
    M_ASN1_D2I_Finish(cert_info, myPROXYCERTINFO_free, ASN1_F_D2I_PROXYCERTINFO);
}

myPROXYCERTINFO * d2i_myPROXYCERTINFO(myPROXYCERTINFO ** cert_info, unsigned char ** pp, long length)
{
  myPROXYCERTINFO *info = d2i_myPROXYCERTINFO_v3(cert_info, pp, length);
  if (!info)
    info = d2i_myPROXYCERTINFO_v4(cert_info, pp, length);
  return info;
}


static int nativeopenssl = 0;

static char *norep()
{
  static char *buffer="";
  return buffer;
}

static void *myproxycertinfo_s2i(UNUSED(struct v3_ext_method *method), UNUSED(struct v3_ext_ctx *ctx), UNUSED(char *data))
{
  return (myPROXYCERTINFO*)data;
}

static char *myproxycertinfo_i2s(UNUSED(struct v3_ext_method *method), void *ext)
{
  myPROXYCERTINFO *pci = NULL;
  char *encoding = NULL;
  char *output = NULL;
  myPROXYPOLICY *pp;
  int dooid = 0;
  char oid[256];

  pci = (myPROXYCERTINFO *)ext;
 
  if (!pci)
    return norep();

  if (pci->path_length) {
    int j = ASN1_INTEGER_get(pci->path_length);

    char *buffer = snprintf_wrap("%X", j);
    output = snprintf_wrap("Path Length Constraint: %s%s\n\n", strlen(buffer)%2 ? "0" : "", buffer);
    free(buffer);
  }
  else
    output = strdup("Path Length Constraint: unlimited\n");

  pp = pci->proxypolicy;

  if (pp && i2t_ASN1_OBJECT(oid, 256, pp->policy_language)) {
    dooid  = 1;
  }

  encoding = snprintf_wrap("%sPolicy Language: %s%s%s%s\n", 
			   output, 
			   ( dooid ? oid : ""), 
			   ( (pp && pp->policy) ? "\nPolicy Text: " : ""), 
         ( (pp && pp->policy) ? (char*)ASN1_STRING_data(pp->policy) : ""),
			   ( (pp && pp->policy) ? "\n" : ""));

  free(output);
  return encoding;
}

void InitProxyCertInfoExtension(int full)
{
#define PROXYCERTINFO_V3      "1.3.6.1.4.1.3536.1.222"
#define PROXYCERTINFO_V4      "1.3.6.1.5.5.7.1.14"
#define OBJC(c,n) OBJ_create(c,n,n)

  X509V3_EXT_METHOD *pcert;
  static int set = 0;
  ASN1_OBJECT *objv3;
  ASN1_OBJECT *objv4;

  if (set)
    return;

  set = 1;


  objv3 = OBJ_txt2obj(PROXYCERTINFO_V3,1);
  objv4 = OBJ_txt2obj(PROXYCERTINFO_V4,1);

  /* Proxy Certificate Extension's related objects */
  if (OBJ_obj2nid(objv3) == 0) {
    ERR_clear_error();
    OBJC(PROXYCERTINFO_V3, "Proxy Certificate Information");
    if (full) {
      pcert = (X509V3_EXT_METHOD *)OPENSSL_malloc(sizeof(X509V3_EXT_METHOD));

      if (pcert) {
        memset(pcert, 0, sizeof(*pcert));
        pcert->ext_nid = OBJ_txt2nid(PROXYCERTINFO_V3);
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
  }

  if (OBJ_obj2nid(objv4) == 0) {
    ERR_clear_error();
    OBJC(PROXYCERTINFO_V4, "Proxy Certificate Information");
    if (full) {
      pcert = (X509V3_EXT_METHOD *)OPENSSL_malloc(sizeof(X509V3_EXT_METHOD));
    
      if (pcert) {
        memset(pcert, 0, sizeof(*pcert));
        pcert->ext_nid = OBJ_txt2nid(PROXYCERTINFO_V4);
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
  }

#ifdef X509_V_FLAG_ALLOW_PROXY_CERTS
  nativeopenssl = 1;
#endif

  ASN1_OBJECT_free(objv3);
  ASN1_OBJECT_free(objv4);

  return;
}

int proxynative(void)
{
  return nativeopenssl;
}
