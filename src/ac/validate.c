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

#include "config.h"
#include "replace.h"

#define _GNU_SOURCE

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

#include "acstack.h"
#include "../api/ccapi/voms_apic.h"
#include "validate.h"
#include "listfunc.h"


#include <stdlib.h>
#include <string.h>

#include "replace.h"

static char *getfqdn(void);
static int checkAttributes(STACK_OF(AC_ATTR) *, struct col *, int);
static int checkExtensions(STACK_OF(X509_EXTENSION) *, X509 *, struct col *, 
			   int);


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
    return "AC not yet (or not anymore) valid.";
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

  
int validate(X509 *cert, X509 *issuer, AC *ac, struct col *voms, int valids)
{
  STACK_OF(GENERAL_NAME) *names;
  GENERAL_NAME  *name;
  ASN1_GENERALIZEDTIME *b;
  ASN1_GENERALIZEDTIME *a;
  EVP_PKEY *key;
  BIGNUM *bn;
  int res;

  if (valids) {
    CHECK(ac);
    CHECK(cert);
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
    CHECK(issuer);
    key=X509_extract_key(issuer);
    int ok = ASN1_verify((int (*)())i2d_AC_INFO,ac->sig_alg, ac->signature,
                         (char *)ac->acinfo, key);
    EVP_PKEY_free(key);
    if (!ok)
      ERROR(AC_ERR_SIGNATURE);
  }

  if (voms) {
    voms->version    = 1;
    voms->siglen     = ac->signature->length;
    voms->signature  = ac->signature->data;
/*     bn               = ASN1_INTEGER_to_BN(ac->acinfo->version, NULL); */
/*     voms->version    = BN_bn2hex(bn); */
/*     BN_free(bn); */
    bn               = ASN1_INTEGER_to_BN(ac->acinfo->serial, NULL);
    voms->serial     = BN_bn2hex(bn);
    BN_free(bn);
    voms->user       = X509_NAME_oneline(X509_get_subject_name(cert), NULL, 0);
    voms->userca     = X509_NAME_oneline(X509_get_issuer_name(cert), NULL, 0);
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

      if (valids & VER_ID) {
        if ((!ac->acinfo->holder->baseid->uid && cert->cert_info->issuerUID) ||
            (!cert->cert_info->issuerUID && ac->acinfo->holder->baseid->uid))
          ERROR(AC_ERR_UID_MISMATCH);
        if (ac->acinfo->holder->baseid->uid) {
          if (M_ASN1_BIT_STRING_cmp(ac->acinfo->holder->baseid->uid,
                                    cert->cert_info->issuerUID))
            ERROR(AC_ERR_UID_MISMATCH);
        }
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
    voms->date1 = strndup(b->data, b->length);
    voms->date2 = strndup(a->data, a->length);
  }

  if (valids & VER_DATE) {
    time_t ctime, dtime;
    time (&ctime);
    ctime += 300;
    dtime = ctime-600;

    if ((a->type != V_ASN1_GENERALIZEDTIME) ||
        (b->type != V_ASN1_GENERALIZEDTIME))
      ERROR(AC_ERR_DATES);

    if (((X509_cmp_current_time(b) >= 0) &&
         (X509_cmp_time(b, &ctime) >= 0)) ||
        ((X509_cmp_current_time(a) <= 0) &&
         (X509_cmp_time(a, &dtime) <= 0)))
      ERROR(AC_ERR_DATES);
  }

  if (valids) {
    if (sk_AC_ATTR_num(ac->acinfo->attrib) == 0)
      ERROR(AC_ERR_ATTRIBS);
  }

  if (voms)
    voms->reserved = (char *)ac;

  if ((res = checkExtensions(ac->acinfo->exts, issuer, voms, valids)))
    return res;

  return checkAttributes(ac->acinfo->attrib, voms, valids);
}

static int checkAttributes(STACK_OF(AC_ATTR) *atts, struct col *voms, int valids)
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

  if (!atts)
    return 0;

  if (voms)
    voms->voname = NULL;


  nid3 = OBJ_txt2nid("idatcap");
  pos3 = X509at_get_attr_by_NID(atts, nid3, -1);

  if (!(pos3 >=0))
    return AC_ERR_ATTRIBS;

  /* get capabilities */
  caps = sk_AC_ATTR_value(atts, pos3);

  if (sk_AC_IETFATTR_num(caps->ietfattr) != 1)
    return AC_ERR_ATTRIB_URI;

  capattr = sk_AC_IETFATTR_value(caps->ietfattr, 0);
  
  values = capattr->values;

  if (sk_GENERAL_NAME_num(capattr->names) != 1)
    return AC_ERR_ATTRIB_URI;

  data = sk_GENERAL_NAME_value(capattr->names, 0);
  if (data->type == GEN_URI) {
    char *point;
    if (voms) {
      voms->voname = strndup(data->d.ia5->data, data->d.ia5->length);
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

  for (i=0; i<sk_AC_IETFATTRVAL_num(values); i++) {

    capname = sk_AC_IETFATTRVAL_value(values, i);

    if (!(capname->type == V_ASN1_OCTET_STRING))
      return AC_ERR_ATTRIB_FQAN;

    if (voms) {
      str  = strndup(capname->data, capname->length);
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

  int pos1 = X509v3_get_ext_by_NID(exts, nid1, -1);
  int pos2 = X509v3_get_ext_by_NID(exts, nid2, -1);
  int pos3 = X509v3_get_ext_by_critical(exts, 1, -1);
  int pos4 = X509v3_get_ext_by_NID(exts, nid3, -1);
  int ret = AC_ERR_UNKNOWN;

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
          ASN1_STRING_set(fqdns, fqdn, strlen(fqdn));
          targets = (AC_TARGETS *)X509V3_EXT_d2i(ex);
          if (targets)
            for (i = 0; i < sk_AC_TARGET_num(targets->targets); i++) {
              name = sk_AC_TARGET_value(targets->targets, i);
              if (name->name && name->name->type == GEN_URI) {
                ok = !ASN1_STRING_cmp(name->name->d.ia5, fqdns);
                if (ok)
                  break;
              }
            }
          ASN1_STRING_free(fqdns);
        }
        if (!ok)
          ret = AC_ERR_EXT_TARGET;
      }
    }
    else
      ret = AC_ERR_EXT_CRIT;
    pos3 = X509v3_get_ext_by_critical(exts, 1, pos3);
  }
  
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
            char hashed[20];
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
