/*
 * Copyright 1999-2006 University of Chicago
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stdio.h>
#include <openssl/err.h>
#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/x509v3.h>
#include <assert.h>

#include "doio.h"

#include "proxycertinfo.h"

typedef PROXY_CERT_INFO_EXTENSION PROXYCERTINFO_OLD;

ASN1_SEQUENCE(PROXYCERTINFO_OLD) =
{
    ASN1_SIMPLE(PROXYCERTINFO_OLD, proxyPolicy, PROXY_POLICY),
    ASN1_EXP_OPT(PROXYCERTINFO_OLD, pcPathLengthConstraint, ASN1_INTEGER, 1),
} ASN1_SEQUENCE_END(PROXYCERTINFO_OLD)

IMPLEMENT_ASN1_FUNCTIONS(PROXYCERTINFO_OLD)
IMPLEMENT_ASN1_DUP_FUNCTION(PROXYCERTINFO_OLD)

static
void*
PROXYCERTINFO_OLD_s2i(
    struct v3_ext_method const* method
  , struct v3_ext_ctx* ctx
  , char const* data
)
{
  return (PROXY_CERT_INFO_EXTENSION*)data;
}

static
char* PROXYCERTINFO_OLD_i2s(struct v3_ext_method* method, void* ext)
{
  PROXY_CERT_INFO_EXTENSION* pci = NULL;
  char *encoding = NULL;
  char *output = NULL;
  PROXY_POLICY *pp;
  int dooid = 0;
  char oid[256];

  pci = (PROXY_CERT_INFO_EXTENSION *)ext;
 
  if (!pci)
    return "";

  if (pci->pcPathLengthConstraint) {
    int j = ASN1_INTEGER_get(pci->pcPathLengthConstraint);

    char *buffer = snprintf_wrap("%X", j);
    output = snprintf_wrap("Path Length Constraint: %s%s\n\n", strlen(buffer)%2 ? "0" : "", buffer);
    free(buffer);
  }
  else
    output = strdup("Path Length Constraint: unlimited\n");

  pp = pci->proxyPolicy;

  if (pp && i2t_ASN1_OBJECT(oid, 256, pp->policyLanguage)) {
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

STACK_OF(CONF_VALUE) * i2v_PROXYCERTINFO_OLD(
    struct v3_ext_method *              method,
    PROXY_CERT_INFO_EXTENSION *         ext,
  STACK_OF(CONF_VALUE) *              extlist);

static int i2r_pci(X509V3_EXT_METHOD *method, PROXY_CERT_INFO_EXTENSION *pci,
                   BIO *out, int indent)
{
    BIO_printf(out, "%*sPath Length Constraint: ", indent, "");
    if (pci->pcPathLengthConstraint)
        i2a_ASN1_INTEGER(out, pci->pcPathLengthConstraint);
    else
        BIO_printf(out, "infinite");
    BIO_puts(out, "\n");
    BIO_printf(out, "%*sPolicy Language: ", indent, "");
    i2a_ASN1_OBJECT(out, pci->proxyPolicy->policyLanguage);
    BIO_puts(out, "\n");
    if (pci->proxyPolicy->policy && pci->proxyPolicy->policy->data)
        BIO_printf(out, "%*sPolicy Text: %s\n", indent, "",
                   pci->proxyPolicy->policy->data);
    return 1;
}

X509V3_EXT_METHOD * PROXYCERTINFO_OLD_x509v3_ext_meth()
{
    static X509V3_EXT_METHOD proxycertinfo_x509v3_ext_meth =
    {
        -1,
        X509V3_EXT_MULTILINE,
        ASN1_ITEM_ref(PROXYCERTINFO_OLD),
        0, 0, 0, 0,
        (X509V3_EXT_I2S) 0,//PROXYCERTINFO_OLD_i2s,
        (X509V3_EXT_S2I) 0,//PROXYCERTINFO_OLD_s2i,
        (X509V3_EXT_I2V) 0 /*i2v_PROXYCERTINFO_OLD*/, 0,
        (X509V3_EXT_I2R) i2r_pci, 0,
        NULL
    };
    return (&proxycertinfo_x509v3_ext_meth);    
}

ASN1_OBJECT * PROXY_POLICY_get_policy_language(
    PROXY_POLICY *                       policy)
{
    return policy->policyLanguage;
}

unsigned char * PROXY_POLICY_get_policy(
    PROXY_POLICY *                       policy,
    int *                               length)
{
    if(policy->policy)
    { 
        (*length) = policy->policy->length;
        if(*length > 0 && policy->policy->data)
        {
            unsigned char *                 copy = malloc(*length);
            memcpy(copy, policy->policy->data, *length);
            return copy;
        }
    }
    
    return NULL;
}

STACK_OF(CONF_VALUE) * i2v_PROXYPOLICY(
    struct v3_ext_method *              method,
    PROXY_POLICY *                       ext,
    STACK_OF(CONF_VALUE) *              extlist)
{
    unsigned char *                     policy = NULL;
    char                                policy_lang[128];
    unsigned char *                     tmp_string = NULL;
    unsigned char *                     index = NULL;
    int                                 nid;
    int                                 policy_length;

    X509V3_add_value("Proxy Policy:", NULL, &extlist);

    nid = OBJ_obj2nid(PROXY_POLICY_get_policy_language(ext));

    if(nid != NID_undef)
    {
        BIO_snprintf(policy_lang, 128, " %s", OBJ_nid2ln(nid));
    }
    else
    {
        policy_lang[0] = ' ';
        i2t_ASN1_OBJECT(&policy_lang[1],
                        127,
                        PROXY_POLICY_get_policy_language(ext));
    }
    
    X509V3_add_value("    Policy Language", 
                     policy_lang,
                     &extlist);
    
    policy = PROXY_POLICY_get_policy(ext, &policy_length);
    
    if(!policy)
    {
        X509V3_add_value("    Policy", " EMPTY", &extlist);
    }
    else
    {
        X509V3_add_value("    Policy:", NULL, &extlist);

        tmp_string = policy;
        while (policy_length > 0)
        {
            int                         policy_line_length;

            index = memchr(tmp_string, '\n', (size_t) policy_length);

            /* Weird to indent the last line only... */
            if (!index)
            {
                char *                  last_string;

                policy_line_length = policy_length;

                last_string = malloc(policy_line_length + 9);
                BIO_snprintf(
                        last_string,
                        (size_t) (policy_line_length +9),
                        "%8s%.*s", "",
                        policy_line_length,
                        (char *) tmp_string);
                X509V3_add_value(NULL, last_string, &extlist);
                free(last_string);
            }
            else
            {
                *(index++) = '\0';
                policy_line_length = index - tmp_string;
                
                X509V3_add_value(NULL, (char *) tmp_string, &extlist);
                
                tmp_string = index;
            }
            policy_length -= policy_line_length;
        }
        
        free(policy);
    }
    
    return extlist;
}

STACK_OF(CONF_VALUE) * i2v_PROXYCERTINFO_OLD(
    struct v3_ext_method *              method,
    PROXY_CERT_INFO_EXTENSION *         ext,
    STACK_OF(CONF_VALUE) *              extlist)
{
    int                                 len = 128;
    char                                tmp_string[128];
    
    if (!ext) {
      extlist = NULL;
      return extlist;
    }

    if (extlist == NULL)
    {
        extlist = sk_CONF_VALUE_new_null();
        if(extlist == NULL)
        { 
            return NULL;
        }
    }
    
    if (PROXY_CERT_INFO_EXTENSION_get_path_length(ext) > -1)
    {
        memset(tmp_string, 0, len);
        BIO_snprintf(tmp_string, len, " %lu (0x%lx)",
                     PROXY_CERT_INFO_EXTENSION_get_path_length(ext),
                     PROXY_CERT_INFO_EXTENSION_get_path_length(ext));
        X509V3_add_value("Path Length", tmp_string, &extlist);
    }

    if(PROXY_CERT_INFO_EXTENSION_get_policy(ext))
    {
        i2v_PROXYPOLICY(NULL,
                        PROXY_CERT_INFO_EXTENSION_get_policy(ext),
                             extlist);
    }


    return extlist;
}

int
PROXY_CERT_INFO_EXTENSION_set_path_length(
    PROXY_CERT_INFO_EXTENSION* pci
  , long pl
) 
{  
  if (pci != NULL) {

    if (pl != -1) {
      if (pci->pcPathLengthConstraint == NULL) {
	pci->pcPathLengthConstraint = ASN1_INTEGER_new();
      }
      return ASN1_INTEGER_set(pci->pcPathLengthConstraint, pl);
    } else {
      ASN1_INTEGER_free(pci->pcPathLengthConstraint);
      pci->pcPathLengthConstraint = NULL;
    }

    return 1;
  }

  return 0;
}

long
PROXY_CERT_INFO_EXTENSION_get_path_length(PROXY_CERT_INFO_EXTENSION const* pci)
{
  if (pci && pci->pcPathLengthConstraint) {
    return ASN1_INTEGER_get(pci->pcPathLengthConstraint);
  } else {
    return -1;
  }
}

int
PROXY_CERT_INFO_EXTENSION_set_policy(
    PROXY_CERT_INFO_EXTENSION* pci
  , PROXY_POLICY* policy
) 
{
  PROXY_POLICY_free(pci->proxyPolicy);

  pci->proxyPolicy = PROXY_POLICY_dup(policy);

  return 1;
}

PROXY_POLICY*
PROXY_CERT_INFO_EXTENSION_get_policy(PROXY_CERT_INFO_EXTENSION const* pci)
{
  if (pci) {
    return pci->proxyPolicy;
  } else {
    return NULL;
  }
}

void InitProxyCertInfoExtension(int full)
{
  static int init_done = 0;

  if (init_done) {
    return;
  }

  char const* pci_v3_sn =  "proxyCertInfo_V3";
  char const* pci_v3_ln =  "Proxy Certificate Information (V3)";
  int const v3nid = OBJ_create(PROXYCERTINFO_OLD_OID, pci_v3_sn, pci_v3_ln);
  assert(v3nid != 0 && "OBJ_create failed");

  if (X509V3_EXT_get_nid(v3nid) == NULL) {
    X509V3_EXT_METHOD* meth = PROXYCERTINFO_OLD_x509v3_ext_meth();
    meth->ext_nid = v3nid;
    X509V3_EXT_add(meth);
  }

  init_done = 1;
}
