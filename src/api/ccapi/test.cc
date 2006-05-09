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

#include <voms_api.h>

extern "C" {
#include <openssl/pem.h>
#include <openssl/x509.h>
}

#include <iostream>

#include <string>


extern "C" {
char *Encode(char *, int, int *);
}

static std::string retmsg[] = { "VERR_NONE", "VERR_NOSOCKET", "VERR_NOIDENT",
                                "VERR_COMM", "VERR_PARAM", "VERR_NOEXT", 
                                "VERR_NOINIT", "VERR_TIME", "VERR_IDCHECK",
                                "VERR_EXTRAINFO", "VERR_FORMAT", "VERR_NODATA",
                                "VERR_PARSE", "VERR_DIR", "VERR_SIGN",
                                "VERR_SERVER", "VERR_MEM", "VERR_VERIFY",
                                "VERR_IDENT", "VERR_TYPE", "VERR_ORDER",
                                "VERR_SERVERCODE", "VERR_NOTAVAIL" };

static STACK_OF(X509) *load_chain(char *certfile);

void printvoms(voms *i)
{
  std::cout << "SIGLEN: " << i->siglen << std::endl << "USER:" << i->user << std::endl
            << "UCA: " << i->userca << std::endl << "SERVER: " << i->server << std::endl
            << "SCA: " << i->serverca << std::endl << "VO: " << i->voname << std::endl
            << "URI: " << i->uri << std::endl << "DATE1: " << i->date1 << std::endl
            << "DATE2: " << i->date2 << std::endl;

  switch (i->type) {
  case TYPE_NODATA:
    std::cout << "NO DATA" << std::endl;
    break;
  case TYPE_CUSTOM:
    std::cout << i->custom << std::endl;
    break;
  case TYPE_STD:
    for (std::vector<data>::iterator j = i->std.begin(); j != i->std.end(); j++)
      std::cout << "GROUP: " << j->group << std::endl
		<< "ROLE: " << j->role << std::endl
		<< "CAP: " << j->cap << std::endl;
    break;
  }
}
void print(vomsdata &d)
{
  std::vector<voms> v = d.data;
  int k = 0;

  for (std::vector<voms>::iterator i=v.begin(); i != v.end(); i++) {
    std::cout << ++k << " ********************************************" << std::endl;
    printvoms(&*i);
#if 0
    std::cout << "SIGLEN: " << i->siglen << std::endl << "USER:" << i->user << std::endl
	      << "UCA: " << i->userca << std::endl << "SERVER: " << i->server << std::endl
	      << "SCA: " << i->serverca << std::endl << "VO: " << i->voname << std::endl
	      << "URI: " << i->uri << std::endl << "DATE1: " << i->date1 << std::endl
	      << "DATE2: " << i->date2 << std::endl;

    switch (i->type) {
    case TYPE_NODATA:
      std::cout << "NO DATA" << std::endl;
      break;
    case TYPE_CUSTOM:
      std::cout << i->custom << std::endl;
      break;
    case TYPE_STD:
      for (std::vector<data>::iterator j = i->std.begin(); j != i->std.end(); j++)
	std::cout << "GROUP: " << j->group << std::endl
		  << "ROLE: " << j->role << std::endl
		  << "CAP: " << j->cap << std::endl;
      break;
    }
#endif
  }
  std::cout << "WORKVO: " << d.workvo << std::endl
	    << "EXTRA: " << d.extra_data << std::endl;
}

int main(int argc, char *argv[])
{
  vomsdata d;
  bool res;

  /*
   * Initializes directory info.
   */

  if (d.RetrieveFromProxy(RECURSE_CHAIN)) {
    print(d);
    std::cout << "LOADING FROM PROXY SUCCEEDED." << std::endl;
  }
  else
    std::cout << "LOADING FROM PROXY FAILED." << std::endl;

  d.LoadSystemContacts();
  d.LoadUserContacts();

  std::vector<contactdata> y = d.FindByAlias("reptest");
  for (std::vector<contactdata>::iterator beg = y.begin(); beg != y.end(); beg++)
    std::cout << beg->nick << " " << beg->host << ":" << beg->port
	     << " [" << beg->contact << "] \"" << beg->vo << "\""
	     << std::endl;
  std::vector<contactdata> w = d.FindByVO("WPtest");
  for (std::vector<contactdata>::iterator beg = w.begin(); beg != w.end(); beg++)
    std::cout << beg->nick << " " << beg->host << ":" << beg->port
	     << " [" << beg->contact << "] \"" << beg->vo << "\""
	     << std::endl;

  std::cerr << "TEST 1" << std::endl;
  /*
   * Contact two different vomses and collect information from both.
   */
  d.Order("Fred:debugger");
  d.Order("Fred/McPant");
  //  res = d.Contact("aaa-test.cnaf.infn.it",15000,"/C=IT/O=INFN/OU=cas server/L=Bologna/CN=cas/aaa-test.cnaf.infn.it/Email=Vincenzo.Ciaschini@cnaf.infn.it", "S1");
  res = d.Contact("datatag6.cnaf.infn.it",13000,"/C=IT/O=INFN/OU=cas server/L=Bologna/CN=cas/aaa-test.cnaf.infn.it/Email=Vincenzo.Ciaschini@cnaf.infn.it", "A");

  if (res)
    print(d);
  else
    std::cerr << "ERROR!" << retmsg[d.error] << std::endl;
  if (!res) {
    std::cerr << "err: " << retmsg[d.error] << std::endl;
  }

  std::cerr << "TEST 1.5" << std::endl;

  /*
   * Unparse info into its original format.
   */
  std::string binary;

  res = d.Export(binary);
  int l;

  if (res)
    std::cout << "------------------\n" << Encode(const_cast<char *>(binary.data()), binary.size(), &l) << "\n-------\n" << std::flush;
  else
    std::cerr << "Error!" << std::endl;
  if (!res) {
    std::cerr << "err: " << retmsg[d.error] << std::endl;
  }

  /*
   * Now convert it back into readable format.
   */
  vomsdata v("/home/marotta/cert","/etc/grid-security/certificates");
  res = v.Import(binary);

  if (res)
    std::cout << "------------------" << std::endl << binary << "-------" << std::endl;
  else
    std::cerr << "Error!" << std::endl;
  if (!res) {
    std::cerr << "err: " << retmsg[v.error] << std::endl;
  }


  std::cerr << "TEST 2" << std::endl;
  /*
   * Get Data from real certificate.
   */

  d.data.clear();

  BIO *in = NULL;
  X509 *x = NULL;

  in = BIO_new(BIO_s_file());
  if (in) {
    if (BIO_read_filename(in, "/tmp/x509up_u500") > 0) {
      x = PEM_read_bio_X509(in, NULL, 0, NULL);
      STACK_OF(X509) *chain = load_chain("/tmp/x509up_u500");
      res = d.Retrieve(x, chain, RECURSE_CHAIN);

      if (res) {
	print(d);
	voms v;

	if (d.DefaultData(v))
	  printvoms(&v);
      }
      else
	std::cerr << "ERROR!" << std::endl;
    }
  }

  if (!res) {
    std::cerr << "err: " << retmsg[d.error] << std::endl;
  }
  std::cerr << std::flush;
  
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
