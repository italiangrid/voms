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
}

#include <string>
#include <vector>

#include "voms_api.h"

extern "C" {
#include <openssl/x509.h>
#include "newformat.h"
#include "listfunc.h"
}




/* 
 * This specification is needed to avoid namespace collisions in this file
 */

struct d {
  char *group;
  char *role;
  char *cap;
};

struct att {
  char *name;
  char *qual;
  char *val;
};

struct att_list {
  char *grantor;
  struct att **attrs;
};

struct full_att {
  struct att_list **list;
};

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

struct col {
  int siglen;        /*!< The length of the VOMS server signature */
  char *signature;   /*!< The VOMS server signature */
  char *user;        /*!< The user's DN, as from his certificate */
  char *userca;      /*!< The CA which signed the user's certificate */
  char *server;      /*!< The VOMS server DN, as from its certificate */
  char *serverca;    /*!< The CA which signed the VOMS certificate */
  char *voname;      /*!< The name of the VO to which the VOMS belongs */
  char *uri;         /*!< The URI of the VOMS server */
  char *date1;       /*!< Beginning of validity of the user info */
  char *date2;       /*!< End of validity of the user info */
  int   type;        /*!< The type of data returned */
  struct d **std;    /*!< User's characteristics */
  char *custom;      /*!< The data returned by an S command */
  int datalen;
  int version;
  char **fqan;    /*!< User's attributes in compact format */
  char *serial;
  struct full_att *atts;
  /* Fields below this line are reserved. */
  char *reserved;
  int reserved2;
  int structtype;
  char *buffer;
  int buflen;
};

extern "C" {
extern int validate(X509 *, X509 *, AC *, struct col *, int);
extern char *get_error(int);
}


#define VER_NONE    0x00
#define VER_DATE    0x01
#define VER_TARGETS 0x02
#define VER_KEYID   0x04
#define VER_SIGN    0x08
#define VER_ID      0x10
#define VER_ALL     0xffffffff

bool vomsdata::verifyac(X509 *cert, X509 *issuer, AC *ac, voms &v)
{
  struct col *vv = NULL;
  int result = 1;

  vv = (struct col *)calloc(1, sizeof(struct col));
  if (!vv) {
    seterror(VERR_MEM, "Out of memory.");
    return false;
  }

  int typ = 0;

  if (ver_type & VERIFY_DATE)   typ |= VER_DATE;
  if (ver_type & VERIFY_TARGET) typ |= VER_TARGETS;
  if (ver_type & VERIFY_KEY)    typ |= VER_KEYID;
  if (ver_type & VERIFY_SIGN)   typ |= VER_SIGN;
  if (ver_type & VERIFY_ID)     typ |= VER_ID;
  if ((ver_type & VERIFY_FULL) == VERIFY_FULL) typ = VER_ALL;

  result = validate(cert, issuer, ac, vv, typ);

  if (!result) {
    v.siglen    = vv->siglen;
    v.signature = std::string(vv->signature, vv->siglen);
    v.user      = vv->user;
    v.userca    = vv->userca;
    v.server    = vv->server;
    v.serverca  = vv->serverca;
    v.voname    = vv->voname;
    v.uri       = vv->uri;
    v.serial    = vv->serial;
    v.date1     = vv->date1;
    v.date2     = vv->date2;
    v.version   = vv->version;

    switch (vv->type) {
    case TYPE_STD:
      v.type = TYPE_STD;
      break;
    case TYPE_CUSTOM:
      v.type = TYPE_CUSTOM;
      break;
    default:
      result = false;
    }

    struct d **datap = (struct d **)(vv->std);
    while (*datap) {
      struct d *dat = *datap;
      ::data d;
      d.group = dat->group ? dat->group : "";
      d.role  = dat->role ? dat->role : "";
      d.cap   = dat->cap ? dat->cap : "";
      v.std.push_back(d);
      free(dat->group);
      //free(dat->role);
      //free(dat->cap);
      free(dat);
      datap++;
    }
    free(vv->std);
    vv->std = NULL;

    char **ctmp = vv->fqan;
    while (*ctmp) {
      v.fqan.push_back(*ctmp);
      free(*ctmp);
      ctmp++;
    }
    free(vv->fqan);
    vv->fqan = NULL;
  }
  else
    seterror(VERR_VERIFY, std::string(get_error(result)));


  if (vv->std) {
    struct d **datap = (struct d **)(vv->std);
    while (*datap) {
      free((*datap)->group);
      free((*datap));
      datap++;
    }
    free(vv->std);
  }    
  if (vv->fqan) {
    char **ctmp = vv->fqan;
    while (*ctmp) {
      free(*ctmp);
      ctmp++;
    }
    free(vv->fqan);
    vv->fqan = NULL;
  }

  int i = 0;
  while (vv->atts->list[i]) {
    struct attributelist l;
    struct att_list *al = vv->atts->list[i];
    l.grantor = std::string(al->grantor);
    int j = 0;
    while (al->attrs[j]) {
      struct attribute a;
      struct att *at = al->attrs[j];

      a.name      = std::string(at->name);
      a.qualifier = std::string(at->qual);
      a.value     = std::string(at->val);

      l.attributes.push_back(a);
      j++;
    }
    v.attributes.push_back(l);
    i++;
  }

  free_full_att(vv->atts);
  free(vv->fqan);
  free(vv->user);
  free(vv->userca);
  free(vv->server);
  free(vv->serverca);
  free(vv->voname);
  free(vv->serial);
  free(vv->date1);
  free(vv->date2);
  free(vv);

  return result == 0;
}
