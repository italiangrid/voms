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
#include "replace.h"

#define _GNU_SOURCE

#include <stddef.h>
#include <openssl/sha.h>
#include <openssl/asn1.h>
#include <openssl/asn1_mac.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/stack.h>
#include <openssl/safestack.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include <openssl/bn.h>

#include "newformat.h"
#include "acerrors.h"

#include "attributes.h"
#include "acstack.h"
#include "../api/ccapi/voms_apic.h"
#include "validate.h"
#include "listfunc.h"


#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "replace.h"

static char *getfqdn(void);
static int checkAttributes(STACK_OF(AC_ATTR) *, struct col *);
static int checkExtensions(STACK_OF(X509_EXTENSION) *,X509 *,struct col *,int);
static int interpret_attributes(AC_FULL_ATTRIBUTES *, struct col *);

static void free_att(struct att *a)
{
  if (a) {
    free(a->name);
    free(a->qual);
    free(a->val);
    free(a);
  }
}

static void free_att_list(struct att_list *at)
{
  if (at) {
    free(at->grantor);
    listfree((char **)(at->attrs), (freefn)free_att);
    free(at);
  }
}

static void free_full_att(struct full_att *fa)
{
  if (fa) {
    listfree((char **)(fa->list), (freefn)free_att_list);
    free(fa);
  }
}

char *get_error(int e)
{
  switch (e) {
  case AC_ERR_UNSET:
  case AC_ERR_SET:
    return "AC structure got corrupted.";
    break;
  case AC_ERR_SIGNATURE:
    return "Failed to verify AC signature.";
    break;
  case AC_ERR_VERSION:
    return "Mismatched AC version.";
    break;
  case AC_ERR_HOLDER_SERIAL:
    return "AC has been granted to a different certificate than the passed one.";
    break;
  case AC_ERR_HOLDER:
    return "Cannot retrieve owner name from AC.";
    break;
  case AC_ERR_UID_MISMATCH:
    return "Incorrectly formatted owner name.";
    break;
  case AC_ERR_ISSUER_NAME:
    return "Cannot discover AC creator.";
    break;
  case AC_ERR_SERIAL:
    return "AC serial number too long.";
    break;
  case AC_ERR_DATES:
    return "AC not yet valid.";
    break;
  case AC_ERR_DATES2:
    return "AC not valid anymore.";
    break;
  case AC_ERR_ATTRIBS:
    return "VOMS Attributes missing from AC.";
    break;
  case AC_ERR_ATTRIB_URI:
    return "VOMS Server contact data missing from AC.";
    break;
  case AC_ERR_ATTRIB_FQAN:
    return "VOMS Attributes absent or misformed.";
    break;
  case AC_ERR_EXTS_ABSENT:
    return "Required AC extensions missing (NoRevAvail and AuthorityKeyIdentifier)";
    break;
  case AC_ERR_MEMORY:
    return "Out of memory.";
    break;
  case AC_ERR_EXT_CRIT:
    return "Unknown critical extension inside AC.";
    break;
  case AC_ERR_EXT_TARGET:
    return "Unable to parse Target extension.";
    break;
  case AC_ERR_TARGET_NO_MATCH:
    return "Cannot find match among allowed hosts.";
    break;
  case AC_ERR_EXT_KEY:
    return "AC issuer key unreadable or unverifiable.";
    break;
  case AC_ERR_UNKNOWN:
    return "Unknown error. (run for the hills!)";
    break;
  case AC_ERR_PARAMETERS:
    return "Parameter error (Internal error: run for the hills!)";
    break;
  case X509_ERR_ISSUER_NAME:
    return "Cannot discover AC Issuer name.";
    break;
  case X509_ERR_HOLDER_NAME:
    return "Cannot discover AC Holder name.";
    break;
  case AC_ERR_NO_EXTENSION:
    return "Cannot create needed extensions.";
    break;
  default:
    return "PANIC: Internal error found!";
    break;
  }
}


#define ERROR(m)   do { return (m); }     while (0)
#define CHECK(a)   do { if ((!a)) ERROR(AC_ERR_UNSET); }  while (0)
#define NCHECK(a)  do { if ((a)) ERROR(AC_ERR_SET); }     while (0)
#define WARNING(a) do { if ((a)) ERROR(AC_ERR_SET); } while (0)

  
int validate(X509 *cert, X509 *issuer, AC *ac, struct col *voms, int valids, time_t vertime)
{
  STACK_OF(GENERAL_NAME) *names;
  GENERAL_NAME  *name = NULL;
  ASN1_GENERALIZEDTIME *b;
  ASN1_GENERALIZEDTIME *a;
  EVP_PKEY *key;
  BIGNUM *bn;
  int res;

  if (valids) {
    CHECK(ac);
    CHECK(ac->acinfo);
    CHECK(ac->acinfo->version);
    CHECK(ac->acinfo->holder);
    NCHECK(ac->acinfo->holder->digest);
    CHECK(ac->acinfo->form);
    CHECK(ac->acinfo->form->names);
    NCHECK(ac->acinfo->form->is);
    NCHECK(ac->acinfo->form->digest);
    CHECK(ac->acinfo->serial);
    CHECK(ac->acinfo->validity);
    CHECK(ac->acinfo->alg);
    CHECK(ac->acinfo->validity);
    CHECK(ac->acinfo->validity->notBefore);
    CHECK(ac->acinfo->validity->notAfter);
    CHECK(ac->acinfo->attrib);
    CHECK(ac->sig_alg);
    CHECK(ac->signature);
  }

  if (valids & VER_SIGN) {
    int ok;
    CHECK(issuer);
    key=X509_extract_key(issuer);
    ok = ASN1_verify((int (*)())i2d_AC_INFO,ac->sig_alg, ac->signature,
                         (char *)ac->acinfo, key);
    EVP_PKEY_free(key);
    if (!ok)
      ERROR(AC_ERR_SIGNATURE);
  }

  if (voms) {
    voms->version    = 1;
    voms->siglen     = ac->signature->length;
    voms->signature  = ac->signature->data;
    bn               = ASN1_INTEGER_to_BN(ac->acinfo->serial, NULL);
    voms->serial     = BN_bn2hex(bn);
    BN_free(bn);
    if (cert) {
      voms->user       = X509_NAME_oneline(X509_get_subject_name(cert), NULL, 0);
      voms->userca     = X509_NAME_oneline(X509_get_issuer_name(cert), NULL, 0);
    }
    else {
      if (valids & VER_ID)
        ERROR(AC_ERR_HOLDER);
      voms->user  = voms->userca = NULL;
    }
    if (issuer) {
      voms->server     = X509_NAME_oneline(X509_get_subject_name(issuer), NULL, 0);
      voms->serverca   = X509_NAME_oneline(X509_get_issuer_name(issuer), NULL, 0);
    }
    else {
      voms->server     = X509_NAME_oneline(sk_GENERAL_NAME_value(ac->acinfo->form->names, 0)->d.dirn,NULL, 0);
      voms->serverca   = strdup("Unable to determine CA");
    }
  }

  if (valids) {
    if (valids & VER_ID) {

      if (ac->acinfo->holder->baseid) {
        CHECK(ac->acinfo->holder->baseid->serial);
        CHECK(ac->acinfo->holder->baseid->issuer);

        if (ASN1_INTEGER_cmp(ac->acinfo->holder->baseid->serial,
                             cert->cert_info->serialNumber))
          ERROR(AC_ERR_HOLDER_SERIAL);

        names = ac->acinfo->holder->baseid->issuer;
        if ((sk_GENERAL_NAME_num(names) != 1))
          ERROR(AC_ERR_HOLDER);
        if (!(name = sk_GENERAL_NAME_value(names,0)))
          ERROR(AC_ERR_HOLDER);
        if (name->type != GEN_DIRNAME)
          ERROR(AC_ERR_HOLDER);
        if (X509_NAME_cmp(name->d.dirn, cert->cert_info->subject) &&
            X509_NAME_cmp(name->d.dirn, cert->cert_info->issuer))
          ERROR(AC_ERR_HOLDER);

        if ((!ac->acinfo->holder->baseid->uid && cert->cert_info->issuerUID) ||
            (!cert->cert_info->issuerUID && ac->acinfo->holder->baseid->uid))
          ERROR(AC_ERR_UID_MISMATCH);
        if (ac->acinfo->holder->baseid->uid) {
          if (M_ASN1_BIT_STRING_cmp(ac->acinfo->holder->baseid->uid,
                                    cert->cert_info->issuerUID))
            ERROR(AC_ERR_UID_MISMATCH);
        }
      }    
      else if (ac->acinfo->holder->name) {
        names = ac->acinfo->holder->name;
        if ((sk_GENERAL_NAME_num(names) == 1) || 
            ((name = sk_GENERAL_NAME_value(names,0))) ||
            (name->type != GEN_DIRNAME)) {
          if (X509_NAME_cmp(name->d.dirn, cert->cert_info->issuer)) {
            /* CHECK ALT_NAMES */
            /* in VOMS ACs, checking into alt names is assumed to always fail. */
            ERROR(AC_ERR_UID_MISMATCH);
          }
        }
      }
    }

    names = ac->acinfo->form->names;

    if ((sk_GENERAL_NAME_num(names) != 1))
      ERROR(AC_ERR_ISSUER_NAME);
    if (!(name = sk_GENERAL_NAME_value(names,0)))
      ERROR(AC_ERR_ISSUER_NAME);
    if (name->type != GEN_DIRNAME) 
      ERROR(AC_ERR_ISSUER_NAME);
    if (valids & VER_ID)
      if (X509_NAME_cmp(name->d.dirn, issuer->cert_info->subject))
        ERROR(AC_ERR_ISSUER_NAME);

    if (ac->acinfo->serial->length>20)
      ERROR(AC_ERR_SERIAL);
  }

  b = ac->acinfo->validity->notBefore;
  a = ac->acinfo->validity->notAfter;

  if (voms) {
    voms->date1 = strndup((const char*)b->data, b->length);
    voms->date2 = strndup((const char*)a->data, a->length);
  }

  if (valids & VER_DATE) {
    time_t ctime, dtime;
    if (vertime == 0) {
      time (&ctime);
      vertime = ctime;
    }
    else
      ctime = vertime;
    ctime += 300;
    dtime = ctime-600;

    if ((a->type != V_ASN1_GENERALIZEDTIME) ||
        (b->type != V_ASN1_GENERALIZEDTIME))
      ERROR(AC_ERR_DATES);

    if (((X509_cmp_time(b, &vertime) >= 0) &&
         (X509_cmp_time(b, &ctime) >= 0))) 
      ERROR(AC_ERR_DATES);
    if (((X509_cmp_time(a, &dtime) <= 0) &&
         (X509_cmp_time(a, &dtime) <= 0)))
      ERROR(AC_ERR_DATES2);
  }

  if (valids) {
    if (sk_AC_ATTR_num(ac->acinfo->attrib) == 0)
      ERROR(AC_ERR_ATTRIBS);
  }

  if (voms)
    voms->reserved = (char *)ac;

  if ((res = checkExtensions(ac->acinfo->exts, issuer, voms, valids)))
    return res;

  return checkAttributes(ac->acinfo->attrib, voms);
}

static int checkAttributes(STACK_OF(AC_ATTR) *atts, struct col *voms)
{
  int nid3;
  int pos3;
  int i;

  AC_ATTR *caps;
  STACK_OF(AC_IETFATTRVAL) *values;
  AC_IETFATTR *capattr;
  AC_IETFATTRVAL *capname;
  GENERAL_NAME *data;

  char **list, **tmp;

  char *str, *str2;
  struct data *d;
  char *g, *r, *c;
  char *rolestart, *capstart;
  struct data **dlist, **dtmp;

  str = str2 = NULL;
  list = tmp = NULL;
  d = NULL;
  dlist = dtmp = NULL;
  data = NULL;

  if (!atts)
    return 0;

  if (voms)
    voms->voname = NULL;


  /* find AC_ATTR with IETFATTR type */
  nid3 = OBJ_txt2nid("idatcap");
  pos3 = X509at_get_attr_by_NID(atts, nid3, -1);
  if (!(pos3 >=0))
    return AC_ERR_ATTRIBS;
  caps = sk_AC_ATTR_value(atts, pos3);
  
  /* check there's exactly one IETFATTR attribute */
  if (sk_AC_IETFATTR_num(caps->ietfattr) != 1)
    return AC_ERR_ATTRIB_URI;

  /* retrieve the only AC_IETFFATTR */
  capattr = sk_AC_IETFATTR_value(caps->ietfattr, 0);
  values = capattr->values;
  
  /* check it has exactly one policyAuthority */
  if (sk_GENERAL_NAME_num(capattr->names) != 1)
    return AC_ERR_ATTRIB_URI;

  /* put policyAuthority in voms struct */
  data = sk_GENERAL_NAME_value(capattr->names, 0);
  if (data->type == GEN_URI) {
    char *point;
    if (voms) {
      voms->voname = strndup((char*)data->d.ia5->data, data->d.ia5->length);
      point = strstr(voms->voname, "://");

      if (point) {
        *point='\0';
        voms->uri = point + 3;
      }
      else return AC_ERR_ATTRIB_URI;
    }
  }
  else
    return AC_ERR_ATTRIB_URI;

  /* scan the stack of IETFATTRVAL to put attribute in voms struct */
  for (i=0; i<sk_AC_IETFATTRVAL_num(values); i++) {
    capname = sk_AC_IETFATTRVAL_value(values, i);

    if (!(capname->type == V_ASN1_OCTET_STRING))
      return AC_ERR_ATTRIB_FQAN;

    if (voms) {
      str  = strndup((char*)capname->data, capname->length);
      str2 = strdup(str);
      d = (struct data *)malloc(sizeof(struct data));

      if (!str || !str2)
        goto err;

      if (!(tmp=listadd(list, str, sizeof(str))))
        goto err;

      list = tmp;

      g = r = c = NULL;

      rolestart = strstr(str2, "/Role=");
      capstart = strstr(str2, "/Capability=");
    
      g = str2;
      str2 = NULL;
      if (rolestart) {
        *rolestart = '\0';
        r = rolestart + 6;
      }

      if (capstart) {
        *capstart = '\0';
        c = capstart + 12;
      }

      d->group = g;
      d->role  = r;
      d->cap   = c;

      if (!(dtmp = (struct data **)listadd((char **)dlist, (char *)d, sizeof(d))))
        goto err;

      dlist = dtmp;
    }
  }

  if (voms) {
    voms->std     = dlist;
    voms->compact = list;
    voms->type    = TYPE_STD;
  }

  return 0;

 err:
  {
    char        **tmp  = list;
    struct data **dtmp = dlist;

    while (*list)
      free(*list++);

    while (*dlist) {
      free ((*dlist)->group);
      free(*dlist++);
    }

    free(tmp);
    free(dtmp);
    free(str);
    free(str2);
    if (voms)
      free(voms->voname);
  }
  return AC_ERR_MEMORY;

}
  
static int checkExtensions(STACK_OF(X509_EXTENSION) *exts, X509 *iss, struct col *voms, int valids)
{
  int nid1 = OBJ_txt2nid("idcenoRevAvail");
  int nid2 = OBJ_txt2nid("authorityKeyIdentifier");
  int nid3 = OBJ_txt2nid("idceTargets");
  int nid5 = OBJ_txt2nid("attributes");

  int pos1 = X509v3_get_ext_by_NID(exts, nid1, -1);
  int pos2 = X509v3_get_ext_by_NID(exts, nid2, -1);
  int pos3 = X509v3_get_ext_by_critical(exts, 1, -1);
  int pos4 = X509v3_get_ext_by_NID(exts, nid3, -1);
  int pos5 = X509v3_get_ext_by_NID(exts, nid5, -1);

  int ret = 0;

  /* noRevAvail, Authkeyid MUST be present */
  if (pos1 < 0 || pos2 < 0)
    return AC_ERR_EXTS_ABSENT;


  /* The only critical extension allowed is idceTargets. */
  while (pos3 >=0) {
    X509_EXTENSION *ex;
    AC_TARGETS *targets;
    AC_TARGET *name;

    ex = sk_X509_EXTENSION_value(exts, pos3);
    if (pos3 == pos4) {
      if (valids & VER_TARGETS) {
        char *fqdn = getfqdn();
        int ok = 0;
        int i;
        ASN1_IA5STRING *fqdns = ASN1_IA5STRING_new();
        if (fqdns) {
          ret = AC_ERR_TARGET_NO_MATCH;
          ASN1_STRING_set(fqdns, fqdn, strlen(fqdn));
          targets = (AC_TARGETS *)X509V3_EXT_d2i(ex);
          if (targets) {
            for (i = 0; i < sk_AC_TARGET_num(targets->targets); i++) {
              name = sk_AC_TARGET_value(targets->targets, i);
              if (name->name && name->name->type == GEN_URI) {
                ok = !ASN1_STRING_cmp(name->name->d.ia5, fqdns);
                if (ok) {
                  ret = 0;
                  break;
                }
              }
            }
            if (!ok) {
              ASN1_STRING_free(fqdns);
              return AC_ERR_TARGET_NO_MATCH;
            }
          }
          ASN1_STRING_free(fqdns);
        }
        if (!ok)
          return AC_ERR_EXT_TARGET;
      }
    }
    else
      return AC_ERR_EXT_CRIT;

    pos3 = X509v3_get_ext_by_critical(exts, 1, pos3);
  }

  voms->atts = NULL;

  if (pos5 >= 0) {
    X509_EXTENSION *ex = NULL;
    AC_FULL_ATTRIBUTES *full_attr = NULL;
    ex = sk_X509_EXTENSION_value(exts, pos5);
    full_attr = (AC_FULL_ATTRIBUTES *)X509V3_EXT_d2i(ex);

    if (full_attr) {
      if (!interpret_attributes(full_attr, voms)) {
        ret = AC_ERR_ATTRIB;
      }
    }
    AC_FULL_ATTRIBUTES_free(full_attr);
  }

  if (ret)
    return ret;

  if (valids & VER_KEYID) {
    if (pos2 >= 0) {
      X509_EXTENSION *ex;
      AUTHORITY_KEYID *key;
      ex = sk_X509_EXTENSION_value(exts, pos2);
      key = (AUTHORITY_KEYID *)X509V3_EXT_d2i(ex);

      if (key) {
        ret = 0;

        if (iss) {
          if (key->keyid) {
            unsigned char hashed[20];

            if (!SHA1(iss->cert_info->key->public_key->data,
                      iss->cert_info->key->public_key->length,
                      hashed))
              ret = AC_ERR_EXT_KEY;
          
            if ((memcmp(key->keyid->data, hashed, 20) != 0) && 
                (key->keyid->length == 20))
              ret = AC_ERR_EXT_KEY;
          }
          else {
            if (!(key->issuer && key->serial))
              ret = AC_ERR_EXT_KEY;
          
            if (M_ASN1_INTEGER_cmp((key->serial),
                                   (iss->cert_info->serialNumber)))
              ret = AC_ERR_EXT_KEY;
	  
            if (key->serial->type != GEN_DIRNAME)
              ret = AC_ERR_EXT_KEY;

            if (X509_NAME_cmp(sk_GENERAL_NAME_value((key->issuer), 0)->d.dirn, 
                              (iss->cert_info->subject)))
              ret = AC_ERR_EXT_KEY;
          }
        }
        else {
          if (!(valids & VER_ID))
            ret = AC_ERR_EXT_KEY;
        }
        AUTHORITY_KEYID_free(key);
      }
      else {
        ret = AC_ERR_EXT_KEY;
      }
    }
  }
  else 
    return 0;

  return ret;
}

static char *getfqdn(void)
{
  static char *name = NULL;
  char hostname[256];
  char domainname[256];

  if (name)
    free(name);
  name = NULL;

  if ((!gethostname(hostname, 255)) && (!getdomainname(domainname, 255))) {
    if ((name = malloc(strlen(hostname)+strlen(domainname)+2))) {
      strcpy(name, hostname);
      if (strcmp(domainname, "(none)")) {
        if (*domainname == '.')
          strcat(name, domainname);
        else {
          strcat(name, ".");
          strcat(name, domainname);
        }
      }
      strcat(name, "\0");
    }
  }
  return name;
}


static int interpret_attributes(AC_FULL_ATTRIBUTES *full_attr, struct col *voms)
{
  struct full_att *fa      = malloc(sizeof(struct full_att));
  struct att_list *al      = NULL;
  struct att      *a       = NULL;
  char *name, *value, *qualifier, *grant;
  GENERAL_NAME *gn = NULL;
  STACK_OF(AC_ATT_HOLDER) *providers = NULL;
  int i;

  name = value = qualifier = grant = NULL;
  if (!fa)
    return 0;

  fa->list = NULL;

  providers = full_attr->providers;

  for (i = 0; i < sk_AC_ATT_HOLDER_num(providers); i++) {
    AC_ATT_HOLDER *holder = sk_AC_ATT_HOLDER_value(providers, i);
    STACK_OF(AC_ATTRIBUTE) *atts = holder->attributes;
    char **tmp = NULL;
    int j;

    al = malloc(sizeof(struct att_list));
    if (!al)
      goto err;

    al->grantor = NULL;
    al->attrs   = NULL;

    for (j = 0; j < sk_AC_ATTRIBUTE_num(atts); j++) {
      AC_ATTRIBUTE *at = sk_AC_ATTRIBUTE_value(atts, j);
      char ** tmp = NULL;

      name      = strndup((const char*)at->name->data,      at->name->length);
      value     = strndup((const char*)at->value->data,     at->value->length);
      qualifier = strndup((const char*)at->qualifier->data, at->qualifier->length);
      if (!name || !value || !qualifier)
        goto err;

      a = malloc(sizeof(struct att));
      a->name = name;
      a->val  = value;
      a->qual = qualifier;
      name = value = qualifier = NULL;

      tmp = listadd((char **)(al->attrs), (char *)a, sizeof(a));
      if (tmp) {
        al->attrs = (struct att **)tmp;
        a = NULL;
      }
      else {
        listfree((char **)(al->attrs), (freefn)free_att);
        goto err;
      }
    }

    gn = sk_GENERAL_NAME_value(holder->grantor, 0);
    grant = strndup((char*)gn->d.ia5->data, gn->d.ia5->length);
    if (!grant)
      goto err;
    
    al->grantor = grant;
    grant = NULL;

    tmp = listadd((char **)(fa->list), (char *)al, sizeof(al));
    if (tmp) {
      fa->list = (struct att_list **)tmp;
      al = NULL;
    }
    else {
      listfree((char **)(fa->list), (freefn)free_att_list);
      goto err;
    }
  }
  voms->atts = fa;
  fa = NULL;

 err:
  free(grant);
  free(name);
  free(value);
  free(qualifier);
  free_att(a);
  free_att_list(al);
  free_full_att(fa);
  if (fa) {
    return 0;
  }
  else
    return 1;

}
