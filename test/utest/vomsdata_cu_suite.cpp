
#include "vomsdata_cu_suite.h"

#include <openssl/pem.h>

void vomsdata_test::setUp() 
{
  userconf = "../../test/vomses";
  v = vomsdata();
  v.LoadUserContacts(userconf);

  nick = "test";
  name = "testVO";
}

void vomsdata_test::tearDown() 
{
}

void vomsdata_test::AddTarget_case()
{
  std::vector<std::string> targets;
  targets.push_back("target1");
  targets.push_back("target2");
  targets.push_back("target3");

  for (std::vector<std::string>::iterator i = targets.begin(); i != targets.end(); i++)
    v.AddTarget(*i);

  CPPUNIT_ASSERT(targets == v.ListTargets());

  v.ResetTargets();

  CPPUNIT_ASSERT(v.ListTargets().empty());
}


void vomsdata_test::FindByAlias_case() 
{
  std::vector<contactdata> servers = v.FindByAlias(nick);
  CPPUNIT_ASSERT(!servers.empty());

  std::vector<contactdata>::iterator beg = servers.begin();
    
  CPPUNIT_ASSERT(beg->nick == "test");
  CPPUNIT_ASSERT(beg->host == "gridit-wn-010.cnaf.infn.it");
  CPPUNIT_ASSERT(beg->contact == "/C=IT/O=INFN/OU=Host/L=CNAF/CN=gridit-wn-010.cnaf.infn.it");
  CPPUNIT_ASSERT(beg->vo == "testVO");
  CPPUNIT_ASSERT(beg->port == 50001);
  CPPUNIT_ASSERT(beg->version == 31);
}

void vomsdata_test::FindByVO_case() 
{
  std::vector<contactdata> servers = v.FindByVO(name);
  CPPUNIT_ASSERT(!servers.empty());

  std::vector<contactdata>::iterator beg = servers.begin();
    
  CPPUNIT_ASSERT(beg->nick == "test");
  CPPUNIT_ASSERT(beg->host == "gridit-wn-010.cnaf.infn.it");
  CPPUNIT_ASSERT(beg->contact == "/C=IT/O=INFN/OU=Host/L=CNAF/CN=gridit-wn-010.cnaf.infn.it");
  CPPUNIT_ASSERT(beg->vo == "testVO");
  CPPUNIT_ASSERT(beg->port == 50001);
  CPPUNIT_ASSERT(beg->version == 31);

}

void vomsdata_test::Contact_case() 
{
  std::vector<contactdata> servers = v.FindByVO(name);
  CPPUNIT_ASSERT(!servers.empty());

  std::vector<contactdata>::iterator beg = servers.begin();
  
  std::string command = "G/testVO";
  
  CPPUNIT_ASSERT(v.Contact(beg->host, 
			   beg->port, 
			   beg->contact, 
			   command));
}

void vomsdata_test::Retrieve_case()
{
  std::vector<std::string> test;
  test.push_back("/testVO/Role=NULL/Capability=NULL");

  // un certificato di prova nella directory test contenente attributi sopra

  std::string certfile = "../../test/x509up_u501";

  // carico il certificato

  X509 * cert = NULL;
  BIO *in = NULL;
  in = BIO_new(BIO_s_file());
  if (BIO_read_filename(in, certfile.c_str()) > 0)
    cert = PEM_read_bio_X509(in, NULL, 0, NULL);

  // carico la chain

  STACK_OF(X509) * chain = NULL;
  STACK_OF(X509_INFO) * sk = NULL;
  X509_INFO * xi;
  int first = 1;

  in = NULL;
  CPPUNIT_ASSERT(chain = sk_X509_new_null());
  CPPUNIT_ASSERT(in = BIO_new_file(certfile.c_str(), "r"));

  // This loads from a file, a stack of x509/crl/pkey sets
  CPPUNIT_ASSERT(sk = PEM_X509_INFO_read_bio(in, NULL, NULL, NULL));

  // scan over it and pull out the certs
  while (sk_X509_INFO_num(sk)) {

    // skip first cert
    if (first) {
      first = 0;
      continue;
    }
  
    xi = sk_X509_INFO_shift(sk);
    if (xi->x509 != NULL) {
      sk_X509_push(chain, xi->x509);
      xi->x509 = NULL;
    }
    
    X509_INFO_free(xi);
  }

  // uso la Retrieve e verifico gli attributi recuperati

  CPPUNIT_ASSERT(v.Retrieve(cert, chain, RECURSE_CHAIN));

  voms data = *(v.data.begin());
  
  std::vector<std::string>::iterator i,j;

  for (i = data.fqan.begin(), j = test.begin(); i != data.fqan.end(), j!= test.end(); i++, j++)
    CPPUNIT_ASSERT(*i == *j);
  
}

void vomsdata_test::Import_case()
{
  /*
  std::vector<std::string> test;
  test.push_back("/testVO/Role=NULL/Capability=NULL");

  Retrieve_case();

  std::string exported;
  CPPUNIT_ASSERT(v.Export(exported));

  vomsdata w;
  CPPUNIT_ASSERT(w.Import(exported));

  voms data = *(w.data.begin());

  std::vector<std::string>::iterator i,j;

  for (i = data.fqan.begin(), j = test.begin(); i != data.fqan.end(), j!= test.end(); i++, j++)
    CPPUNIT_ASSERT(*i == *j);
  */
}
