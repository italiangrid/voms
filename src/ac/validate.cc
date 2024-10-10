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

#ifdef _GNU_SOURCE
#undef _GNU_SOURCE
#endif

#define _GNU_SOURCE

extern "C" {

#include <stddef.h>
#include <openssl/sha.h>
#include <openssl/asn1.h>
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

#include "attributes.h"
#include "acstack.h"
#include "listfunc.h"
#include "doio.h"
#include "ssl_compat.h"

#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "replace.h"
}

#include "../api/ccapi/voms_api.h"
#include "../api/ccapi/realdata.h"

#include <string>

static std::string getfqdn(void);
static int checkAttributes(STACK_OF(AC_ATTR) *, voms&);
static int checkExtensions(STACK_OF(X509_EXTENSION) *,X509 *, int, realdata *);
static int interpret_attributes(AC_FULL_ATTRIBUTES *, realdata*);

std::string get_error(int e)
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
    return "VOMS Attributes absent or malformed.";
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

#define CTOCPPSTR(var, str) do {    \
    char *s = (str);                \
    var = std::string( s ? s : ""); \
    free(s);                        \
  } while (0)

int validate(X509 *cert, X509 *issuer, AC *ac, voms &v, verify_type valids, time_t vertime, struct realdata *rd)
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

  if (valids & VERIFY_SIGN) {
    int ok;
    CHECK(issuer);
    key=X509_extract_key(issuer);
    ok = AC_verify(ac->sig_alg, ac->signature, (char *)ac->acinfo, key);
    EVP_PKEY_free(key);
    if (!ok)
      ERROR(AC_ERR_SIGNATURE);
  }

  v.version    = 1;
  v.siglen     = ac->signature->length;
  v.signature  = std::string((char*)ac->signature->data, ac->signature->length);
  bn               = ASN1_INTEGER_to_BN(ac->acinfo->serial, NULL);
  char *bnstring = BN_bn2hex(bn);
  v.serial     = std::string(bnstring);
  OPENSSL_free(bnstring);
  BN_free(bn);

  if (cert) {
    CTOCPPSTR(v.user,   X509_NAME_oneline(X509_get_subject_name(cert), NULL, 0));
    CTOCPPSTR(v.userca, X509_NAME_oneline(X509_get_issuer_name(cert), NULL, 0));
  }
  else {
    if (valids & VERIFY_ID)
      ERROR(AC_ERR_HOLDER);
    v.user  = v.userca = "";
  }
  if (issuer) {
    CTOCPPSTR(v.server,   X509_NAME_oneline(X509_get_subject_name(issuer), NULL, 0));
    CTOCPPSTR(v.serverca, X509_NAME_oneline(X509_get_issuer_name(issuer), NULL, 0));
  }
  else {
    CTOCPPSTR(v.server, X509_NAME_oneline(sk_GENERAL_NAME_value(ac->acinfo->form, 0)->d.dirn,NULL, 0));
    v.serverca   = "Unable to determine CA";
  }

  if (valids) {
    if (valids & VERIFY_ID) {

      if (ac->acinfo->holder->baseid) {
        CHECK(ac->acinfo->holder->baseid->serial);
        CHECK(ac->acinfo->holder->baseid->issuer);

        if (ASN1_INTEGER_cmp(ac->acinfo->holder->baseid->serial,
                             X509_get_serialNumber(cert)))
          ERROR(AC_ERR_HOLDER_SERIAL);

        names = ac->acinfo->holder->baseid->issuer;
        if ((sk_GENERAL_NAME_num(names) != 1))
          ERROR(AC_ERR_HOLDER);
        if (!(name = sk_GENERAL_NAME_value(names,0)))
          ERROR(AC_ERR_HOLDER);
        if (name->type != GEN_DIRNAME)
          ERROR(AC_ERR_HOLDER);
        if (X509_NAME_cmp(name->d.dirn, X509_get_subject_name(cert)) &&
            X509_NAME_cmp(name->d.dirn, X509_get_issuer_name(cert)))
          ERROR(AC_ERR_HOLDER);

        ASN1_BIT_STRING const* issuer_uid;
        X509_get0_uids(cert, &issuer_uid, 0);
        if ((!ac->acinfo->holder->baseid->uid && issuer_uid) ||
            (!issuer_uid && ac->acinfo->holder->baseid->uid))
          ERROR(AC_ERR_UID_MISMATCH);
        if (ac->acinfo->holder->baseid->uid) {
          if (ASN1_STRING_cmp(ac->acinfo->holder->baseid->uid,
                                    issuer_uid))
            ERROR(AC_ERR_UID_MISMATCH);
        }
      }    
      else if (ac->acinfo->holder->name) {
        STACK_OF(GENERAL_NAMES) *gnames = ac->acinfo->holder->name;
        GENERAL_NAMES *gname;
        if ((sk_GENERAL_NAMES_num(gnames) == 1) || 
            ((gname = sk_GENERAL_NAMES_value(gnames,0)))) {
          if ((sk_GENERAL_NAME_num(gname) == 1) ||
              ((name = sk_GENERAL_NAME_value(gname,0)) ||
               (name->type != GEN_DIRNAME))) {
            if (X509_NAME_cmp(name->d.dirn, X509_get_issuer_name(cert))) {
              /* CHECK ALT_NAMES */
              /* in VOMS ACs, checking into alt names is assumed to always fail. */
              ERROR(AC_ERR_UID_MISMATCH);
            }
          }
        }
      }
    }

    names = ac->acinfo->form;

    if ((sk_GENERAL_NAME_num(names) != 1))
      ERROR(AC_ERR_ISSUER_NAME);
    if (!(name = sk_GENERAL_NAME_value(names,0)))
      ERROR(AC_ERR_ISSUER_NAME);
    if (name->type != GEN_DIRNAME) 
      ERROR(AC_ERR_ISSUER_NAME);
    if (valids & VERIFY_ID)
      if (X509_NAME_cmp(name->d.dirn, X509_get_subject_name(issuer)))
        ERROR(AC_ERR_ISSUER_NAME);

    if (ac->acinfo->serial->length>20)
      ERROR(AC_ERR_SERIAL);
  }

  b = ac->acinfo->validity->notBefore;
  a = ac->acinfo->validity->notAfter;

  v.date1 = std::string((char*)b->data, b->length);
  v.date2 = std::string((char*)a->data, a->length);

  if (valids & VERIFY_DATE) {
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

  if ((res = checkExtensions(ac->acinfo->exts, issuer, valids, rd)))
    return res;

  res = checkAttributes(ac->acinfo->attrib, v);

  if (res == 0)
    rd->ac = ac;

  return res;
}

static int checkAttributes(STACK_OF(AC_ATTR) *atts, voms &v)
{
  int nid3;
  int pos3;

  AC_ATTR *caps;
  STACK_OF(AC_IETFATTRVAL) *values;
  AC_IETFATTR *capattr;
  AC_IETFATTRVAL *capname;
  GENERAL_NAME *data;

  if (!atts)
    return 0;

  /* find AC_ATTR with IETFATTR type */
  nid3 = OBJ_txt2nid("idatcap");
  pos3 = X509at_get_attr_by_NID((STACK_OF(X509_ATTRIBUTE)*)atts, nid3, -1);
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
    v.voname = std::string((char*)data->d.ia5->data, data->d.ia5->length);
    std::string::size_type point = v.voname.find("://");

    if (point != std::string::npos) {
      v.uri    = v.voname.substr(point + 3);
      v.voname = v.voname.substr(0, point);
    }
    else 
      return AC_ERR_ATTRIB_URI;
  }
  else
    return AC_ERR_ATTRIB_URI;

  std::string top_group = "/" + v.voname;

  /* scan the stack of IETFATTRVAL to put attribute in voms struct */
  for (int i=0; i<sk_AC_IETFATTRVAL_num(values); i++) {
    capname = sk_AC_IETFATTRVAL_value(values, i);

    if (!(capname->type == V_ASN1_OCTET_STRING))
      return AC_ERR_ATTRIB_FQAN;

    std::string str  = std::string((char*)capname->data, capname->length);
    std::string::size_type top_group_size = top_group.size();
    std::string::size_type str_size = str.size();

    /* The top level group name must be identical to the VO name.
       An attribute may end right after the group name, or may continue on
       (separated by a "/"). */
    if (str.compare(0, top_group_size, top_group)) {
      return AC_ERR_ATTRIB_FQAN;
    }
    else if (str_size > top_group_size && str[top_group_size] != '/') {
      return AC_ERR_ATTRIB_FQAN;
    }

    v.fqan.push_back(str);

    struct data d;

    std::string::size_type rolestart = str.find("/Role=");
    std::string::size_type capstart  = str.find("/Capability=");

    if (capstart != std::string::npos) {
      if (rolestart != std::string::npos) {
        d.group = str.substr(0, rolestart);
        d.role  = str.substr(rolestart + 6, capstart - rolestart -6);
        d.cap   = str.substr(capstart + 12);
      }
      else {
        d.group = str.substr(0, capstart);
        d.role  = "";
        d.cap   = str.substr(capstart + 12);
      }
    } 
    else {
      if (rolestart != std::string::npos) {
        d.group = str.substr(0, rolestart);
        d.role  = str.substr(rolestart+6);
        d.cap   = "";
      }
      else {
        d.group = str;
        d.role  = "";
        d.cap   = "";
      }
    }

    v.std.push_back(d);
  }


  v.type    = TYPE_STD;

  return 0;
}
  
static int checkExtensions(STACK_OF(X509_EXTENSION) *exts, X509 *iss, int valids, realdata *rd)
{
  int nid1 = NID_no_rev_avail;
  int nid2 = NID_authority_key_identifier;
  int nid3 = NID_target_information;
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
      if (valids & VERIFY_TARGET) {
        std::string fqdn = getfqdn();
        int ok = 0;
        ASN1_IA5STRING *fqdns = ASN1_IA5STRING_new();
        if (fqdns) {
          ret = AC_ERR_TARGET_NO_MATCH;
          ASN1_STRING_set(fqdns, fqdn.c_str(), fqdn.size());
          targets = (AC_TARGETS *)X509V3_EXT_d2i(ex);

          if (targets) {
            for (int i = 0; i < sk_AC_TARGET_num(targets->targets); i++) {
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
              AC_TARGETS_free(targets);              
              return AC_ERR_TARGET_NO_MATCH;
            }
          }
          AC_TARGETS_free(targets);
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

  if (pos5 >= 0) {
    X509_EXTENSION *ex = NULL;
    AC_FULL_ATTRIBUTES *full_attr = NULL;
    ex = sk_X509_EXTENSION_value(exts, pos5);
    full_attr = (AC_FULL_ATTRIBUTES *)X509V3_EXT_d2i(ex);

    if (full_attr) {
      if (!interpret_attributes(full_attr, rd)) {
        ret = AC_ERR_ATTRIBS;
      }
    }
    AC_FULL_ATTRIBUTES_free(full_attr);
  }

  if (ret)
    return ret;

  if (valids & VERIFY_KEY) {
    if (pos2 >= 0) {
      X509_EXTENSION *ex;
      AUTHORITY_KEYID *key;
      ex = sk_X509_EXTENSION_value(exts, pos2);
      key = (AUTHORITY_KEYID *)X509V3_EXT_d2i(ex);

      if (key) {
        ret = 0;

        if (iss) {
          if (key->keyid) {
            unsigned char hashed[SHA_DIGEST_LENGTH];

            ASN1_BIT_STRING* pubkey = X509_get0_pubkey_bitstr(iss);
            if (!SHA1(pubkey->data,
                      pubkey->length,
                      hashed))
              ret = AC_ERR_EXT_KEY;
          
            if ((memcmp(key->keyid->data, hashed, 20) != 0) && 
                (key->keyid->length == 20))
              ret = AC_ERR_EXT_KEY;
          }
          else {
            if (!(key->issuer && key->serial))
              ret = AC_ERR_EXT_KEY;
          
            if (ASN1_INTEGER_cmp((key->serial),
                                (X509_get0_serialNumber(iss))))
              ret = AC_ERR_EXT_KEY;
	  
            if (key->serial->type != GEN_DIRNAME)
              ret = AC_ERR_EXT_KEY;

            if (X509_NAME_cmp(sk_GENERAL_NAME_value((key->issuer), 0)->d.dirn, 
                              (X509_get_subject_name(iss))))
              ret = AC_ERR_EXT_KEY;
          }
        }
        else {
          if (!(valids & VERIFY_ID))
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

static std::string getfqdn(void)
{
  char hostname[256];
  char domainname[256];

  if ((!gethostname(hostname, 255)) && (!getdomainname(domainname, 255))) {
    if (!strcmp(domainname, "(none)")) {
      domainname[0]='\0';

      return std::string(hostname) + (domainname[0] == '.' ? "." : "") + domainname;
    }
  }
  return "";
}


static int interpret_attributes(AC_FULL_ATTRIBUTES *full_attr, realdata *rd)
{
  GENERAL_NAME *gn = NULL;
  STACK_OF(AC_ATT_HOLDER) *providers = NULL;

  providers = full_attr->providers;

  for (int i = 0; i < sk_AC_ATT_HOLDER_num(providers); i++) {
    AC_ATT_HOLDER *holder = sk_AC_ATT_HOLDER_value(providers, i);
    STACK_OF(AC_ATTRIBUTE) *atts = holder->attributes;

    struct attributelist al;

    for (int j = 0; j < sk_AC_ATTRIBUTE_num(atts); j++) {
      AC_ATTRIBUTE *at = sk_AC_ATTRIBUTE_value(atts, j);

      struct attribute a;
      a.name      = std::string((char*)at->name->data,      at->name->length);
      a.value     = std::string((char*)at->value->data,     at->value->length);
      a.qualifier = std::string((char*)at->qualifier->data, at->qualifier->length);

      al.attributes.push_back(a);
    }

    gn = sk_GENERAL_NAME_value(holder->grantor, 0);
    al.grantor = std::string((char*)gn->d.ia5->data, gn->d.ia5->length);

    rd->attributes->push_back(al);
  }

  /*
   * Deal with voms-server < 1.9, which generated an empty AC_FULL_ATTRIBUTES
   * extension when no GAs were present, rather than omitting the extension
   * in its entirety, which would have been the right behaviour.
   */
  return !(sk_AC_ATT_HOLDER_num(providers)) || (rd->attributes->size() != 0);

}
