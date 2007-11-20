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

#include <stdio.h>
#include <cinterface.h>

#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/x509.h>
#include <openssl/err.h>

static char *retmsg[] = { "VERR_NONE", "VERR_NOSOCKET", "VERR_NOIDENT", "VERR_COMM", 
			  "VERR_PARAM", "VERR_NOEXT", "VERR_NOINIT",
			  "VERR_TIME", "VERR_IDCHECK", "VERR_EXTRAINFO",
			  "VERR_FORMAT", "VERR_NODATA", "VERR_PARSE",
			  "VERR_DIR", "VERR_SIGN", "VERR_SERVER", 
			  "VERR_MEM", "VERR_VERIFY", "VERR_IDENT",
			  "VERR_TYPE" };

static STACK_OF(X509) *load_chain(char *certfile);

void printvoms(struct vomsr *v)
{
  int j;

  printf("SIGLEN: %d\nUSER: %s\n", v->siglen, v->user);
  printf("UCA: %s\nSERVER: %s\n", v->userca, v->server);
  printf("SCA: %s\nVO: %s\n", v->serverca, v->voname);
  printf("URI: %s\nDATE1: %s\n", v->uri, v->date1);
  printf("DATE2: %s\n", v->date2);

  switch (v->type) {
  case TYPE_NODATA:
    printf("NO DATA\n");
    break;
  case TYPE_CUSTOM:
    printf("%*s\n", v->datalen - 10, v->custom);
    break;
  case TYPE_STD:
    j = 0;
    while (v->std[j]) {
      printf("GROUP: %s\nROLE: %s\nCAP: %s\n",v->std[j]->group,
	     v->std[j]->role,v->std[j]->cap);
      j++;
    }
  }
}
void print(struct vomsdatar *d)
{
  struct vomsr **vo = d->data;
  struct vomsr *v;
  int k = 0;

  while(vo[k]) {
    v = vo[k++];
    printf("%d *******************************************\n",k);
    printvoms(v);
  }

  if (d->workvo)
    printf("WORKVO: %s\n", d->workvo);

  if (d->extra_data)
    printf("EXTRA: %s\n", d->extra_data);
}

int main(int argc, char *argv[])
{
  struct vomsdatar *vd = VOMS_Init(NULL, NULL);
  int err;
  int res = 1;
  BIO *in = NULL;
  X509 *x = NULL;
  STACK_OF(X509) *chain;
  struct contactdatar **ll, **pp;
  char *data = NULL;
  int len;

  if (!vd) {
    printf("ERR:!\n");
    exit(0);
  }
  /*
   * Initializes directory info.
   */

  pp = ll = VOMS_FindByAlias(vd, "timtest",NULL, NULL, &err);
  if (ll) {
    while (*ll) {
      printf("%s %s:%d [%s] \"%s\"\n", (*ll)->nick, (*ll)->host, (*ll)->port,
	     (*ll)->contact, (*ll)->vo);
      ll++;
    }
  }
  VOMS_DeleteContacts(pp);

#if 1
  ll = pp = VOMS_FindByVO(vd, "timtest",NULL, NULL, &err);
  if (pp) {
    while (*pp) {
      printf("%s %s:%d [%s] \"%s\"\n", (*pp)->nick, (*pp)->host, (*pp)->port,
	     (*pp)->contact, (*pp)->vo);
      pp++;
    }
  }
  VOMS_DeleteContacts(ll);
#endif

  printf("TEST 1\n");
  /*
   * Contact two different vomses and collect information from both.
   */
  /*   if (VOMS_Ordering("Fred:debugger", vd, &err)) */
  /*     VOMS_Ordering("timtestFred/McPant", vd, &err); */
  /*
    res = VOMS_Contact("aaa-test.cnaf.infn.it",15000,"/C=IT/O=INFN/OU=cas server/L=Bologna/CN=cas/aaa-test.cnaf.infn.it/Email=Vincenzo.Ciaschini@cnaf.infn.it", "S1",vd, &err);
  */
  res &= VOMS_Contact("datatag6.cnaf.infn.it",21000,"/C=IT/O=INFN/OU=Host/L=CNAF/CN=datatag6.cnaf.infn.it", "G/timtest",vd, &err);

  if (res)
    print(vd);
  else
    printf("ERROR!\n");
  if (!res) {
    printf("err: %s\n", retmsg[err]);
  }

  printf("EXPORTING....\n");

  if (VOMS_Export(&data, &len, vd, &err)) {
    printf("EXPORTED...\n");
    VOMS_Destroy(vd);
    vd = VOMS_Init(NULL,NULL);
    printf("IMPORTING...\n");
    if (VOMS_Import(data, len, vd, &err)) {
      printf("IMPORTED...\n");
      print(vd);
    }
    else
      printf("err: %s\n", retmsg[err]);
  }
  else
    printf("err: %s\n", retmsg[err]);
  
  VOMS_Destroy(vd);

  printf("TEST 2\n");
  /*
   * Get Data from real certificate.
   */

  vd = VOMS_Init(NULL, NULL);

  in = BIO_new(BIO_s_file());
  chain = load_chain("/tmp/x509up_u502");
  ERR_print_errors_fp(stderr);
  if (in) {
    if (BIO_read_filename(in, "/tmp/x509up_u502") > 0) {
      x = PEM_read_bio_X509(in, NULL, 0, NULL);

      res = VOMS_Retrieve(x, chain, RECURSE_CHAIN, vd, &err);

      if (res) {
        struct vomsr *v;
        struct vomsr *new;
        print(vd);

        v = VOMS_DefaultData(vd, &err);
        if (err == VERR_NONE)
          printvoms(v);

        new = VOMS_Copy(v, &err);
        printvoms(new);
      }
      else
        printf("ERROR!\n");
    }
  }

  BIO_free(in);
  VOMS_Destroy(vd);

  if (!res) {
    printf("err: %s\n", retmsg[err]);
  }
  
  exit(0);
}

static STACK_OF(X509) *load_chain(char *certfile)
{
  STACK_OF(X509_INFO) *sk=NULL;
  STACK_OF(X509) *stack=NULL, *ret=NULL;
  BIO *in=NULL;
  X509_INFO *xi;
  int first = 1;

  if(!(stack = sk_X509_new_null())) {
    printf("memory allocation failure\n");
    goto end;
  }

  if(!(in=BIO_new_file(certfile, "r"))) {
    printf("error opening the file, %s\n",certfile);
    goto end;
  }

  /* This loads from a file, a stack of x509/crl/pkey sets */
  if(!(sk=PEM_X509_INFO_read_bio(in,NULL,NULL,NULL))) {
    /*     if(!(sk=PEM_X509_read_bio(in,NULL,NULL,NULL))) { */
    printf("error reading the file, %s\n",certfile);
    goto end;
  }

  /* scan over it and pull out the certs */
  while (sk_X509_INFO_num(sk)) {
    /* skip first cert */
    if (first) {
      first = 0;
      continue;
    }
    xi=sk_X509_INFO_shift(sk);
    if (xi->x509 != NULL) {
      sk_X509_push(stack,xi->x509);
      xi->x509=NULL;
    }
    X509_INFO_free(xi);
  }
  if(!sk_X509_num(stack)) {
    printf("no certificates in file, %s\n",certfile);
    sk_X509_free(stack);
    goto end;
  }
  ret=stack;
end:
  BIO_free(in);
  sk_X509_INFO_free(sk);
  return(ret);
}
