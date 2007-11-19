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
  char *Encode(char *, int, int *, int);
}

static std::string retmsg[] = { "VERR_NONE", "VERR_NOSOCKET", "VERR_NOIDENT",
                                "VERR_COMM", "VERR_PARAM", "VERR_NOEXT", 
                                "VERR_NOINIT", "VERR_TIME", "VERR_IDCHECK",
                                "VERR_EXTRAINFO", "VERR_FORMAT", "VERR_NODATA",
                                "VERR_PARSE", "VERR_DIR", "VERR_SIGN",
                                "VERR_SERVER", "VERR_MEM", "VERR_VERIFY",
                                "VERR_IDENT", "VERR_TYPE", "VERR_ORDER",
                                "VERR_SERVERCODE", "VERR_NOTAVAIL" };

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
    std::cout << "------------------\n" << Encode(const_cast<char *>(binary.data()), binary.size(), &l,1) << "\n-------\n" << std::flush;
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

  
  FILE *f = fopen("/tmp/x509up_u502", "rb");
  d.Retrieve(f, RECURSE_CHAIN);
  fclose(f);

  f = fopen("/tmp/x509up_u502", "rb");
  d.Retrieve(f, RECURSE_CHAIN);
  fclose(f);

  print(d);
  voms vv;

  if (d.DefaultData(vv))
    printvoms(&vv);

  if (!res) {
    std::cerr << "err: " << retmsg[d.error] << std::endl;
  }
  std::cerr << std::flush;
  
  exit(0);
}
