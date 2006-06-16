/*********************************************************************
 *
 * Authors: Valerio Venturi - Valerio.Venturi@cnaf.infn.it
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

#include <stdio.h>

#include <openssl/err.h>
#include <openssl/asn1_mac.h>
#include <openssl/objects.h>

#include "proxycertinfo.h"

/* PROXYPOLICY function */

PROXYPOLICY * PROXYPOLICY_new() {

  ASN1_CTX                            c;
  PROXYPOLICY *                       ret;

  ret = NULL;

  M_ASN1_New_Malloc(ret, PROXYPOLICY);
  ret->policy_language = OBJ_nid2obj(OBJ_sn2nid(IMPERSONATION_PROXY_SN));
  ret->policy = NULL;
  return (ret);
  M_ASN1_New_Error(ASN1_F_PROXYPOLICY_NEW);

}

void PROXYPOLICY_free(PROXYPOLICY * policy) {

  if(policy == NULL) return;

  ASN1_OBJECT_free(policy->policy_language);
  M_ASN1_OCTET_STRING_free(policy->policy);
  OPENSSL_free(policy);

}

/* duplicate */
PROXYPOLICY * PROXYPOLICY_dup(PROXYPOLICY * policy) {
  return ((PROXYPOLICY *) ASN1_dup((int (*)())i2d_PROXYPOLICY,
				   (char *(*)())d2i_PROXYPOLICY,
				   (char *)policy));
}

/* set policy language */
int PROXYPOLICY_set_policy_language(PROXYPOLICY * policy, ASN1_OBJECT * policy_language) {

  if(policy_language != NULL) 
    {
      ASN1_OBJECT_free(policy->policy_language);
      policy->policy_language = OBJ_dup(policy_language);
      return 1;
    }
  return 0;

}

/* get policy language */
ASN1_OBJECT * PROXYPOLICY_get_policy_language(PROXYPOLICY * policy)
{
    return policy->policy_language;
}

/* set policy */
int PROXYPOLICY_set_policy(PROXYPOLICY * proxypolicy, unsigned char * policy, int length) {

  if(policy != NULL) {

    /* perchè questa copia? */
    unsigned char * copy = malloc(length);
    memcpy(copy, policy, length);

    /* if member policy of proxypolicy non set */
    if(!proxypolicy->policy)
      proxypolicy->policy = ASN1_OCTET_STRING_new();
      
    /* set member policy of proxypolicy */
    ASN1_OCTET_STRING_set(proxypolicy->policy, copy, length);

  }
  
  else if(proxypolicy->policy) 
    ASN1_OCTET_STRING_free(proxypolicy->policy);

  return 1;

}

/* get policy */
unsigned char * PROXYPOLICY_get_policy(PROXYPOLICY * proxypolicy, int * length) {

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
  /* else return NULL */
  return NULL;

}

/* internal to der conversion */
int i2d_PROXYPOLICY(PROXYPOLICY * policy, unsigned char ** pp) 
{
#if 0
  int                                 v1 = 0;
    
  M_ASN1_I2D_vars(policy);

  M_ASN1_I2D_len(policy->policy_language, i2d_ASN1_OBJECT);
  M_ASN1_I2D_len_EXP_opt(policy->policy, i2d_ASN1_OCTET_STRING, 0, v1);
  M_ASN1_I2D_seq_total();
  M_ASN1_I2D_put(policy->policy_language, i2d_ASN1_OBJECT);
  M_ASN1_I2D_put_EXP_opt(policy->policy, i2d_ASN1_OCTET_STRING, 0, v1);

  M_ASN1_I2D_finish();
#endif

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

PROXYPOLICY * d2i_PROXYPOLICY(PROXYPOLICY ** a, unsigned char ** pp, long length)
{
    M_ASN1_D2I_vars(a, PROXYPOLICY *, PROXYPOLICY_new);
    
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
                      PROXYPOLICY_free, 
                      ASN1_F_D2I_PROXYPOLICY);
}



/* PROXYCERTINFO function */

PROXYCERTINFO * PROXYCERTINFO_new() {

  PROXYCERTINFO *                     ret;
  ASN1_CTX                            c;

  ret = NULL;

  M_ASN1_New_Malloc(ret, PROXYCERTINFO);
  memset(ret, (int) NULL, sizeof(PROXYCERTINFO));
  ret->path_length      = NULL;
  ret->proxypolicy           = PROXYPOLICY_new();
  return (ret);
  M_ASN1_New_Error(ASN1_F_PROXYCERTINFO_NEW);

}

void PROXYCERTINFO_free(PROXYCERTINFO * proxycertinfo) {
 
  /* assure proxycertinfo not empty */ 
  if(proxycertinfo == NULL) return;
  
  ASN1_INTEGER_free(proxycertinfo->path_length);
  PROXYPOLICY_free(proxycertinfo->proxypolicy);
  OPENSSL_free(proxycertinfo);

}

/* set path_length */
int PROXYCERTINFO_set_path_length(PROXYCERTINFO * proxycertinfo, long path_length) {
  
  /* assure proxycertinfo is not empty */
  if(proxycertinfo != NULL) {

    if(path_length != -1) {
      /* if member path_length is empty allocate memory the set */
      if(proxycertinfo->path_length == NULL)
	proxycertinfo->path_length = ASN1_INTEGER_new();
      return ASN1_INTEGER_set(proxycertinfo->path_length, path_length);
    }

    else 
      if(proxycertinfo->path_length != NULL) {
	ASN1_INTEGER_free(proxycertinfo->path_length);
	proxycertinfo->path_length = NULL;
      }

    return 1;
  }

  return 0;

}

int PROXYCERTINFO_set_version(PROXYCERTINFO * proxycertinfo, int version)
{
  if (proxycertinfo != NULL) {
    proxycertinfo->version = version;
    return 1;
  }
  return 0;
}

int PROXYCERTINFO_get_version(PROXYCERTINFO * proxycertinfo)
{
  if (proxycertinfo)
    return proxycertinfo->version;
  return -1;
}


/* get path length */
long PROXYCERTINFO_get_path_length(PROXYCERTINFO * proxycertinfo) {

  if(proxycertinfo && proxycertinfo->path_length)
    return ASN1_INTEGER_get(proxycertinfo->path_length);
  else return -1;

}

/* set policy */
int PROXYCERTINFO_set_proxypolicy(PROXYCERTINFO * proxycertinfo, PROXYPOLICY * proxypolicy) {

  PROXYPOLICY_free(proxycertinfo->proxypolicy);

  if(proxypolicy != NULL)
    proxycertinfo->proxypolicy = PROXYPOLICY_dup(proxypolicy);
  else
    proxycertinfo->proxypolicy = NULL;

  return 1;

}

/* get policy */
PROXYPOLICY * PROXYCERTINFO_get_proxypolicy(PROXYCERTINFO * proxycertinfo) {

  if(proxycertinfo)
    return proxycertinfo->proxypolicy;

  return NULL;

}

/* internal to der conversion */
static int i2d_PROXYCERTINFO_v3(PROXYCERTINFO * proxycertinfo, unsigned char ** pp) {

    int                                 v1;

    M_ASN1_I2D_vars(proxycertinfo);
    
    v1 = 0;

    M_ASN1_I2D_len(proxycertinfo->proxypolicy, i2d_PROXYPOLICY);

    M_ASN1_I2D_len_EXP_opt(proxycertinfo->path_length,i2d_ASN1_INTEGER, 1, v1);
    M_ASN1_I2D_seq_total();
    M_ASN1_I2D_put(proxycertinfo->proxypolicy, i2d_PROXYPOLICY);
    M_ASN1_I2D_put_EXP_opt(proxycertinfo->path_length, i2d_ASN1_INTEGER, 1, v1);
    M_ASN1_I2D_finish();

}

static int i2d_PROXYCERTINFO_v4(PROXYCERTINFO * proxycertinfo, unsigned char ** pp) 
{
    M_ASN1_I2D_vars(proxycertinfo);

    if(proxycertinfo->path_length)
    { 
        M_ASN1_I2D_len(proxycertinfo->path_length, i2d_ASN1_INTEGER);
    }
    
    M_ASN1_I2D_len(proxycertinfo->proxypolicy, i2d_PROXYPOLICY);

    M_ASN1_I2D_seq_total();
    if(proxycertinfo->path_length)
    { 
        M_ASN1_I2D_put(proxycertinfo->path_length, i2d_ASN1_INTEGER);
    }
    M_ASN1_I2D_put(proxycertinfo->proxypolicy, i2d_PROXYPOLICY);
    M_ASN1_I2D_finish();
}

int i2d_PROXYCERTINFO(PROXYCERTINFO * proxycertinfo, unsigned char ** pp) 
{
  switch(proxycertinfo->version) {
  case 3:
    return i2d_PROXYCERTINFO_v3(proxycertinfo, pp);
    break;

  case 4:
    return i2d_PROXYCERTINFO_v4(proxycertinfo, pp);
    break;

  default:
    return -1;
    break;
  }
}

static PROXYCERTINFO * d2i_PROXYCERTINFO_v3(PROXYCERTINFO ** cert_info, unsigned char ** pp, long length)
{
    M_ASN1_D2I_vars(cert_info, PROXYCERTINFO *, PROXYCERTINFO_new);

    M_ASN1_D2I_Init();
    M_ASN1_D2I_start_sequence();

    M_ASN1_D2I_get(ret->proxypolicy, d2i_PROXYPOLICY);

    M_ASN1_D2I_get_EXP_opt(ret->path_length, d2i_ASN1_INTEGER, 1);

    ret->version = 3;
    M_ASN1_D2I_Finish(cert_info, PROXYCERTINFO_free, ASN1_F_D2I_PROXYCERTINFO);
}

static PROXYCERTINFO * d2i_PROXYCERTINFO_v4(PROXYCERTINFO ** cert_info, unsigned char ** pp, long length)
{
    M_ASN1_D2I_vars(cert_info, PROXYCERTINFO *, PROXYCERTINFO_new);

    M_ASN1_D2I_Init();
    M_ASN1_D2I_start_sequence();

    M_ASN1_D2I_get_EXP_opt(ret->path_length, d2i_ASN1_INTEGER, 1);
    
    M_ASN1_D2I_get_opt(ret->path_length, d2i_ASN1_INTEGER, V_ASN1_INTEGER);

    M_ASN1_D2I_get(ret->proxypolicy,d2i_PROXYPOLICY);

    ret->version = 4;
    M_ASN1_D2I_Finish(cert_info, PROXYCERTINFO_free, ASN1_F_D2I_PROXYCERTINFO);
}

PROXYCERTINFO * d2i_PROXYCERTINFO(PROXYCERTINFO ** cert_info, unsigned char ** pp, long length)
{
  if (!d2i_PROXYCERTINFO_v3(cert_info, pp, length))
    return d2i_PROXYCERTINFO_v4(cert_info, pp, length);
}
