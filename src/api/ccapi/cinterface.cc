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

#ifndef NOGLOBUS
#include <gssapi.h>
#endif

#include "voms_api.h"

/*Interface routines from C++ API to C API */
extern "C" {
#include "cinterface.h"
#include <stdlib.h>
}




#if 1
int TranslateVOMS(struct vomsdatar *vd, std::vector<voms> &v, int *error)
{
  if (vd->data) {
    /* Delete old store */
    free(vd->data[0]);
    free(vd->data);
  }
  int vsize = v.size();
  
  struct vomsr **arr2 = (struct vomsr **)malloc((vsize+1) * sizeof(struct vomsr *));
  int i = 0;

  if (arr2) {
    std::vector<voms>::iterator cur = v.begin();
    while (cur != v.end()) {
      arr2[i] = cur->translate();
      i++;
      cur++;
    }
    arr2[i] = NULL;
    
    vd->data = arr2;
    return 1;
  }
  free(arr2);
  return 0;
}
#endif

extern "C" {

static char *
mystrdup(const std::string &str)
{
  if (str.empty())
    return NULL;
  else {
    char *res = strdup(str.c_str());
    if (!res)
      throw std::bad_alloc();
    return res;
  }
}

struct vomsdatar *VOMS_Init(char *voms, char *cert)
{
  struct vomsdatar *vd = NULL;
  try {
    vomsdata *v = new vomsdata((voms ? std::string(voms) : ""),
                               (cert ? std::string(cert) : ""));

    if ((vd = (struct vomsdatar *)malloc(sizeof(struct vomsdatar)))) {
      vd->cdir = mystrdup(voms ? std::string(voms) : "");
      vd->vdir = mystrdup(cert ? std::string(cert) : "");
      vd->data = NULL;
      vd->extra_data = vd->workvo = NULL;
      vd->volen = vd->extralen = 0;
      vd->real = v;
    }
  }
  catch(...) {}
  
  return vd;
}


static struct contactdatar **Arrayize(std::vector<contactdata> &cd, int *error)
{

  if (cd.empty())
    return NULL;

  int size1 = cd.size() * sizeof(struct contactdatar);
  int size2 = (cd.size()+1) * sizeof(struct contactdatar *);

  struct contactdatar **cdr = (struct contactdatar **)malloc(size2);
  struct contactdatar *cda = (struct contactdatar *)malloc(size1);

  if (cdr && cda) {
    std::vector<contactdata>::iterator cur = cd.begin(),
      end = cd.end();

    int i = 0;
    while (cur != end) {
      cdr[i] = &cda[i];

      cda[i].nick    = mystrdup(cur->nick.c_str());
      cda[i].host    = mystrdup(cur->host.c_str());
      cda[i].contact = mystrdup(cur->contact.c_str());
      cda[i].vo      = mystrdup(cur->vo.c_str());
      cda[i].port    = cur->port;
      cda[i].version = cur->version;
      i++;
      cur++;
    }
    cdr[i] = NULL;
    
    return cdr;
  }
  else {
    *error = VERR_MEM;
    free (cdr);
    free(cda);
    return NULL;
  }
}

struct contactdatar **VOMS_FindByVO(struct vomsdatar *vd, char *vo,
                                    char *system, char *user, int *error)
{
  if (!vd || !vd->real || !vo || !error) {
    *error = VERR_PARAM;
    return NULL;
  }

  vomsdata *v = (vomsdata *)vd->real;

  (void)v->LoadSystemContacts(system ? std::string(system) : "");
  (void)v->LoadUserContacts(user ? std::string(user) : "");

  std::vector<contactdata> cd = v->FindByVO(vo);

  if (!cd.empty())
    return Arrayize(cd, error);

  *error = v->error;
  return NULL;
}

struct contactdatar **VOMS_FindByAlias(struct vomsdatar *vd, char *vo,
                                       char *system, char *user, int *error)
{
  if (!vd || !vd->real || !vo || !error) {
    *error = VERR_PARAM;
    return NULL;
  }

  vomsdata *v = (vomsdata *)vd->real;

  (void)v->LoadSystemContacts(system ? std::string(system) : "");
  (void)v->LoadUserContacts(user ? std::string(user) : "");

  std::vector<contactdata> cd = v->FindByAlias(vo);

  if (!cd.empty())
    return Arrayize(cd, error);

  *error = v->error;
  return NULL;
}

void VOMS_DeleteContacts(struct contactdatar **list)
{
  if (list) {
    free(list[0]);
    free(list);
  }
}


struct vomsr *voms::translate()
{
  struct vomsr *dst = NULL;

  if ((dst = (struct vomsr *)calloc(1, sizeof(struct vomsr)))) {
    try {
      dst->version   = version;
      dst->siglen    = siglen;
      dst->signature = mystrdup(signature);
      dst->user      = mystrdup(user);
      dst->userca    = mystrdup(userca);
      dst->server    = mystrdup(server);
      dst->serverca  = mystrdup(serverca);
      dst->voname    = mystrdup(voname);
      dst->uri       = mystrdup(uri);
      dst->date1     = mystrdup(date1);
      dst->date2     = mystrdup(date2);
      dst->type      = type;
      dst->custom    = mystrdup(custom);
      dst->serial    = mystrdup(serial);
      dst->datalen   = custom.size();

      dst->ac     = (AC *)  ASN1_dup((int(*)())i2d_AC,   (char*(*)())d2i_AC,   (char *)ac);
      dst->holder = (X509 *)ASN1_dup((int(*)())i2d_X509, (char*(*)())d2i_X509, (char *)holder);

      if (!dst->holder || !dst->ac)
        throw 3;

      dst->fqan = (char **)calloc(1, sizeof(char *)*(fqan.size()+1));
      dst->std  = (struct datar **)calloc(1, sizeof(struct datar *)*(std.size()+1));
      if (!dst->fqan || !dst->std)
        throw 3;

      int j = 0;

      for (std::vector<std::string>::iterator i = fqan.begin();
           i != fqan.end(); i++)
        if (!(dst->fqan[j++] = mystrdup(*i)))
          throw 3;
    
      j = 0;
      for (std::vector<data>::iterator i = std.begin();
             i != std.end(); i++) {
        struct datar *d = (struct datar *)calloc(1, sizeof(struct datar));
        if (d) {
          dst->std[j++] = d;
          d->group = mystrdup(i->group);
          d->role  = mystrdup(i->role);
          d->cap   = mystrdup(i->cap);
        }
        else
          throw 3;
      }

      return dst;
    }
    catch (...) {
      VOMS_Delete(dst);
      return NULL;
    }
  }
  return NULL;
}

void VOMS_Delete(struct vomsr *v) 
{
  if (v) {
    if (v->fqan) {
      int i = 0;
      while(v->fqan[i])
        free(v->fqan[i++]);
      free(v->fqan);
    }
    if (v->std) {
      int i = 0;
      while(v->std[i]) {
        free(v->std[i]->group);
        free(v->std[i]->role);
        free(v->std[i]->cap);
        free(v->std[i++]);
      }
      free (v->std);
    }

    free(v->signature);
    free(v->user);
    free(v->userca);
    free(v->server);
    free(v->serverca);
    free(v->voname);
    free(v->uri);
    free(v->date1);
    free(v->date2);
    free(v->custom);
    free(v->serial);
    AC_free(v->ac);
    X509_free(v->holder);
  }

  free(v);
}

struct vomsdatar *VOMS_CopyALL(struct vomsdatar *vd, int *error)
{
  if (!vd || !vd->real || !error) {
    *error = VERR_PARAM;
    return NULL;
  }

  vomsdata *v = (vomsdata *)vd->real;
  struct vomsdatar *dst = NULL;

  try {
    vomsdata *vn = new vomsdata(*v);
    dst = (struct vomsdatar *)calloc(1, sizeof(struct vomsdatar));
    dst->real       = vn;
    dst->cdir       = mystrdup(vd->cdir);
    dst->vdir       = mystrdup(vd->vdir);
    dst->workvo     = mystrdup(vd->workvo);
    dst->extra_data = mystrdup(vd->extra_data);
    dst->volen      = vd->volen;
    dst->extralen   = vd->extralen;

    /* get size */
    int i = 0;
    while(vd->data[i++]);

    dst->data = (struct vomsr **)calloc(1, sizeof(struct vomsr *)*i);
    for (int j = 0; j < i; j++) {
      dst->data[i] = VOMS_Copy(vd->data[i], error);
      if (!dst->data)
        throw 3;
    }
  }
  catch(...) {
    *error = VERR_MEM;
    VOMS_Destroy(dst);
    return NULL;
  }
  return dst;
}

void VOMS_Destroy(struct vomsdatar *vd)
{
  if (vd) {
    free(vd->cdir);
    free(vd->vdir);
    free(vd->workvo);
    free(vd->extra_data);
    if (vd->data) {
      int i = 0;
      while (vd->data[i])
        VOMS_Delete(vd->data[i++]);
    }
    free(vd->data);
    delete vd->real;
    free(vd);
  }
}


int VOMS_AddTarget(struct vomsdatar *vd, char *target, int *error)
{
  if (!vd || !vd->real || !error) {
    *error = VERR_PARAM;
    return 0;
  }

  vomsdata *v = vd->real;

  if (target)
    v->AddTarget(std::string(target));

  return 1;
}

void VOMS_FreeTargets(struct vomsdatar *vd, int *error)
{
  if (!vd || !vd->real || !error) {
    *error = VERR_PARAM;
    return;
  }

  vomsdata *v = vd->real;

  v->ResetTargets();
}

char *VOMS_ListTargets(struct vomsdatar *vd, int *error)
{

  vomsdata *v = vd->real;

  std::vector<std::string> list = v->ListTargets();

  std::vector<std::string>::iterator cur = list.begin();

  std::string total = "";

  while(cur != list.end()) {
    if (cur != list.begin())
      total += ",";
    total += *cur;
  }

  char *res = mystrdup(total.c_str());
  if (!res)
    *error = VERR_MEM;
  return res;
}

int VOMS_SetVerificationType(int type, struct vomsdatar *vd, int *error)
{
  vomsdata *v = vd->real;

  v->SetVerificationType(verify_type(type));

  return 1;
}

int VOMS_SetLifetime(int length, struct vomsdatar *vd, int *error)
{
  if (!vd || !vd->real || !error) {
    *error = VERR_PARAM;
    return 0;
  }

  vomsdata *v = vd->real;
  v->SetLifetime(length);
  return 1;
}

int VOMS_Ordering(char *order, struct vomsdatar *vd, int *error)
{
  if (!vd || !vd->real || !error) {
    *error = VERR_PARAM;
    return 0;
  }

  if (order) {
    vomsdata *v = vd->real;
    v->Order(std::string(order));
  }

  return 1;
}

int VOMS_ResetOrder(struct vomsdatar *vd, int *error)
{
  if (!vd || !vd->real || !error) {
    *error = VERR_PARAM;
    return 0;
  }

  vomsdata *v = vd->real;
  v->ResetOrder();
  return 1;
}


int VOMS_Contact(char *host, int port, char *servsub, char *comm, struct vomsdatar *vd, int *error)
{
  if (!vd || !vd->real || !error) {
    *error = VERR_PARAM;
    return 0;
  }

  vomsdata *v = vd->real;
  if (v->Contact(std::string(host), port, std::string(servsub), std::string(comm))) {
    return TranslateVOMS(vd, v->data, error);
  }

  *error = v->error;
  return 0;
}

int VOMS_ContactRaw(char *host, int port, char *servsub, char *comm, void **data,
                    int *datalen, int *version, struct vomsdatar *vd, int *error)
{
  if (!host || !port || !servsub || !comm || !data || !datalen || !version ||
      !vd || !vd->real || !error) {
    *error = VERR_PARAM;
    return 0;
  }

  vomsdata *v = vd->real;

  std::string output;
  
  if (v->ContactRaw(std::string(host), port, std::string(servsub),
                    std::string(comm), output, *version)) {
    *datalen = output.size();
    char *d = (char *)malloc(output.size());
    if (d) {
      memcpy(d, output.data(), *datalen);
      *data = d;
      return 1;
    }
    else {
      *error = VERR_MEM;
      return 0;
    }
  }

  *error = v->error;
  return 0;
}

int VOMS_Retrieve(X509 *cert, STACK_OF(X509) *chain, int how,
                  struct vomsdatar *vd, int *error)
{
  if (!cert || !vd || !vd->real || !error || (!chain && how == RECURSE_CHAIN)) {
    *error = VERR_PARAM;
    return 0;
  }
  
  vomsdata *v = vd->real;

  if (v->Retrieve(cert, chain, recurse_type(how)))
    return TranslateVOMS(vd, v->data, error);

  *error = v->error;
  return 0;
}

int VOMS_RetrieveEXT(X509_EXTENSION *ext, struct vomsdatar *vd, int *error)
{
  if (!ext || !vd || !vd->real || !error) {
    *error = VERR_PARAM;
    return 0;
  }
  
  vomsdata *v = vd->real;

  if (v->Retrieve(ext))
    return TranslateVOMS(vd, v->data, error);

  *error = v->error;
  return 0;
}

int VOMS_RetrieveFromCred(gss_cred_id_t cred, int how, struct vomsdatar *vd, int *error)
{
  if (!vd || !vd->real || !error) {
    *error = VERR_PARAM;
    return 0;
  }
  
  vomsdata *v = vd->real;

  if (v->RetrieveFromCred(cred, recurse_type(how)))
    return TranslateVOMS(vd, v->data, error);

  *error = v->error;
  return 0;
}

int VOMS_RetrieveFromCtx(gss_ctx_id_t ctx, int how, struct vomsdatar *vd, int *error)
{
  if (!vd || !vd->real || !error) {
    *error = VERR_PARAM;
    return 0;
  }
  
  vomsdata *v = vd->real;

  if (v->RetrieveFromCtx(ctx, recurse_type(how)))
    return TranslateVOMS(vd, v->data, error);

  *error = v->error;
  return 0;
}

int VOMS_RetrieveFromProxy(int how, struct vomsdatar *vd, int *error)
{
  if (!vd || !vd->real || !error) {
    *error = VERR_PARAM;
    return 0;
  }

  vomsdata *v = vd->real;

  if (v->RetrieveFromProxy(recurse_type(how)))
    return TranslateVOMS(vd, v->data, error);

  *error = v->error;
  return 0;
}

int VOMS_Import(char *buffer, int buflen, struct vomsdatar *vd, int *error)
{
  if (!buffer || !buflen || !vd || !vd->real || !error) {
    *error = VERR_PARAM;
    return 0;
  }

  vomsdata *v = vd->real;

  if (v->Import(std::string(buffer, buflen)))
    return TranslateVOMS(vd, v->data, error);

  *error = v->error;
  return 0;
}

int VOMS_Export(char **buffer, int *buflen, struct vomsdatar *vd, int *error)
{

  if (!buffer || !buflen || !vd || !vd->real || !error) {
    *error = VERR_PARAM;
    return 0;
  }

  vomsdata *v = vd->real;

  std::string data;
  if (v->Export(data)) {
    *buflen = data.size();

    char *d;
    if ((d = (char *)malloc(*buflen))) {
      memcpy(d, data.data(), *buflen);
      *buffer = d;
      return 1;
    }
    else {
      *error = VERR_MEM;
      return 0;
    }
  }

  *error = v->error;
  return 0;
}

struct vomsr *VOMS_DefaultData(struct vomsdatar *vd, int *error)
{
  if (!vd || !error) {
    *error = VERR_PARAM;
    return NULL;
  }

  return vd->data[0];
}

struct vomsr *VOMS_Copy(struct vomsr *org, int *error)
{
  *error = VERR_MEM;

  char **arrf = NULL;
  struct datar **arrd = NULL;
  struct vomsr *dst = NULL;

  if ((dst = (struct vomsr *)calloc(1, sizeof(struct vomsr)))) {
    try {
      dst->version   = org->version;
      dst->siglen    = org->siglen;
      dst->signature = mystrdup(org->signature);
      dst->user      = mystrdup(org->user);
      dst->userca    = mystrdup(org->userca);
      dst->server    = mystrdup(org->server);
      dst->serverca  = mystrdup(org->serverca);
      dst->voname    = mystrdup(org->voname);
      dst->uri       = mystrdup(org->uri);
      dst->date1     = mystrdup(org->date1);
      dst->date2     = mystrdup(org->date2);
      dst->type      = org->type;
      dst->custom    = mystrdup(org->custom);
      dst->serial    = mystrdup(org->serial);
      dst->datalen   = org->datalen;

      dst->ac     = (AC *)  ASN1_dup((int(*)())i2d_AC,   (char*(*)())d2i_AC,   (char *)org->ac);
      dst->holder = (X509 *)ASN1_dup((int(*)())i2d_X509, (char*(*)())d2i_X509, (char *)org->holder);

      if (!dst->holder || !dst->ac)
        throw 3;


      int size = 0;
      while (org->fqan[size++])
        ;

      dst->fqan = (char **)calloc(1, sizeof(char *)*size);

      size = 0;
      while (org->std[size++])
        ;

      dst->std  = (struct datar **)calloc(1, sizeof(struct datar *)*size);
      if (!arrf || !arrd)
        throw 3;

      int j = 0;

      while(org->fqan[j]) {
        if (!(arrf[j] = mystrdup(org->fqan[j])))
          throw 3;
        j++;

      }

      j = 0;

      while (org->std[j]) {
        struct datar *d = (struct datar *)calloc(1, sizeof(struct datar));
        if (d) {
          arrd[j++] = d;
          d->group = mystrdup(org->std[j]->group);
          d->role  = mystrdup(org->std[j]->role);
          d->cap   = mystrdup(org->std[j]->cap);
        }

        if (!d || !d->group || !d->role || !d->cap)
          throw 3;
      }

      return dst;
    }
    catch (...) {
      VOMS_Delete(dst);
      return NULL;
    }
  }
  return NULL;
}

char *VOMS_ErrorMessage(struct vomsdatar *vd, int error, char *buffer, int len)
{
  if (!vd || !vd->real || (buffer && !len)) {
    return NULL;
  }

  vomsdata *v = vd->real;

  std::string msg;

  switch (error) {
  case VERR_MEM:
    msg = "Out of memory.";
    break;
  case VERR_PARAM:
    msg = "Parameters incorrect.";
    break;
  default:
    msg = v->ErrorMessage();
    break;
  }

  if (buffer) {
    if ((msg.size()+1) <= (unsigned int)len) {
      strcpy(buffer, msg.c_str());
      return buffer;
    }
    else
      return NULL;
  }
  else {
    char *buf = (char*)malloc(msg.size()+1);
    if (buf)
      strcpy(buf, msg.c_str());
    return buf;
  }
}
vomsdatar *VOMS_Duplicate(vomsdatar *orig)
{
  struct vomsdatar *vd = NULL;

  try {
    vomsdata *v = new vomsdata(*(orig->real));

    if ((vd = (struct vomsdatar *)malloc(sizeof(struct vomsdatar)))) {
      int error = 0;

      vd->cdir = (orig->cdir ? strdup(orig->cdir) : NULL );
      vd->vdir = (orig->vdir ? strdup(orig->vdir) : NULL );
      //      vd->data = NULL;
      vd->extra_data = (orig->extra_data ? strdup(orig->extra_data) : NULL);
      vd->workvo = (orig->workvo ? strdup(orig->workvo) : NULL);
      vd->volen = orig->volen;
      vd->extralen = orig->extralen;
      vd->real = v;

      if (!TranslateVOMS(vd, v->data, &error)) {
        VOMS_Destroy(vd);
        vd = NULL;
      }
    }
  }
  catch(...) {}
  
  return vd;
}

AC *VOMS_GetAC(vomsr *v)
{
  return (AC *)ASN1_dup((int (*)())i2d_AC, (char * (*)())d2i_AC, (char *)v->ac);
}

}
