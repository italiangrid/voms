
#include "capi_cu_suite.h"
#include <iostream>
#include <openssl/pem.h>

void capi_test::setUp() 
{
  std::cout << std::endl << "Starting up ..." << std::endl;

}

void capi_test::tearDown() 
{
  std::cout << "Tearing down ..." << std::endl;

}

void capi_test::VOMS_Init_case()
{
}

void capi_test::VOMS_FindByAlias_case()
{
  struct vomsdata * v = VOMS_Init("", "");
  int error;
  struct contactdata ** servers = VOMS_FindByAlias(v,
						   "test",
						   0,
						   "./vomses",
						   &error);
  CPPUNIT_ASSERT(servers != NULL);
  
  for(int i=0; servers[i] != NULL; ++i)
  {
    struct contactdata * beg = servers[i];
    CPPUNIT_ASSERT(strcmp(beg->nick, "test") == 0);
    CPPUNIT_ASSERT(strcmp(beg->host, "gridit-wn-010.cnaf.infn.it") == 0);
    CPPUNIT_ASSERT(strcmp(beg->contact, "/C=IT/O=INFN/OU=Host/L=CNAF/CN=gridit-wn-010.cnaf.infn.it") == 0);
    CPPUNIT_ASSERT(strcmp(beg->vo, "testVO") == 0);
    CPPUNIT_ASSERT(beg->port == 50001);
  }

  VOMS_DeleteContacts(servers);
}

void capi_test::VOMS_FindByVO_case(){

  struct vomsdata * v = VOMS_Init("", "");
  int error = 0;
  struct contactdata ** servers = VOMS_FindByVO(v,
						"testVO",
						"",
						"./vomses",
						&error);

  CPPUNIT_ASSERT(servers != NULL);
  
  for(int i=0; servers[i] != NULL; ++i)
  {
    struct contactdata * beg = servers[i];
    CPPUNIT_ASSERT(strcmp(beg->nick, "test") == 0);
    CPPUNIT_ASSERT(strcmp(beg->host, "gridit-wn-010.cnaf.infn.it") == 0);
    CPPUNIT_ASSERT(strcmp(beg->contact, "/C=IT/O=INFN/OU=Host/L=CNAF/CN=gridit-wn-010.cnaf.infn.it") == 0);
    CPPUNIT_ASSERT(strcmp(beg->vo, "testVO") == 0);
    CPPUNIT_ASSERT(beg->port == 50001);
  }



}

void capi_test::VOMS_DeleteContacts_case() 
{
  struct vomsdata * v = VOMS_Init("", "");
  int error;
  struct contactdata ** servers = VOMS_FindByAlias(v,
						"test",
					        "",
						"./vomses",
						&error);

  CPPUNIT_ASSERT(servers != NULL);

  VOMS_DeleteContacts(servers);

  CPPUNIT_ASSERT(servers == NULL);
}

void capi_test::VOMS_AddTarget_case()
{
  struct vomsdata * v = VOMS_Init("", "");
  int error;
  CPPUNIT_ASSERT (VOMS_AddTarget(v,
				 "target",
				 &error) != 0);

}

void capi_test::VOMS_FreeTargets_case()
{
}

void capi_test::VOMS_ListTargets_case()
{
  struct vomsdata * v = VOMS_Init("", "");
  int error;
  CPPUNIT_ASSERT (VOMS_AddTarget(v,
				 "",
				 &error) != 0);
  
  std::cout << VOMS_ListTargets(v, &error) << std::endl;
}

void capi_test::VOMS_Ordering_case()
{

}

void capi_test::VOMS_ResetOrder_case()
{

}

void capi_test::VOMS_Copy_case(){}
void capi_test::VOMS_CopyAll_case(){}
void capi_test::VOMS_Delete_case(){}
void capi_test::VOMS_SetVerificationType_case(){}
void capi_test::VOMS_SetLifetime_case(){}
void capi_test::VOMS_Destro_case(){}

void capi_test::VOMS_Contact_case()
{
  struct vomsdata * v = VOMS_Init( "/etc/grid-security/vomsdir",
				   "/etc/grid-security/certificates" );
  int error;

  struct contactdata ** servers = VOMS_FindByAlias(v,
						"test",
						"",
						"./vomses",
						&error);

  CPPUNIT_ASSERT(servers);

  CPPUNIT_ASSERT(VOMS_Contact((*servers)->host,
			      (*servers)->port,
			      (*servers)->contact,
			      "G/testVO",
			      v,
			      &error));

}

void capi_test::VOMS_Retrieve_case()
{
  /* un certificato di prova nella directory test contenente
   attributi sopra */

  std::string certfile = "x509up_u501";

  /* carico il certificato */

  X509 * cert = NULL;
  BIO *in = NULL;
  in = BIO_new(BIO_s_file());
  if (BIO_read_filename(in, certfile.c_str()) > 0)
    cert = PEM_read_bio_X509(in, NULL, 0, NULL);

  /* carico la chain */

  STACK_OF(X509) * chain = NULL;
  STACK_OF(X509_INFO) * sk = NULL;
  X509_INFO * xi;
  int first = 1;

  in = NULL;
  CPPUNIT_ASSERT(chain = sk_X509_new_null());
  CPPUNIT_ASSERT(in = BIO_new_file(certfile.c_str(), "r"));

  /* This loads from a file, a stack of x509/crl/pkey sets */
  CPPUNIT_ASSERT(sk = PEM_X509_INFO_read_bio(in, NULL, NULL, NULL));

  /* scan over it and pull out the certs */
  while (sk_X509_INFO_num(sk)) {

    /* skip first cert */
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

  /* uso la Retrieve e verifico gli attributi recuperati */

  struct vomsdata * v = VOMS_Init( "/etc/grid-security/vomsdir",
				   "/etc/grid-security/certificates" );
  int error;
  CPPUNIT_ASSERT(VOMS_Retrieve(cert, 
			       chain, 
			       RECURSE_CHAIN,
			       v,
			       &error));

} 


void capi_test::VOMS_Import_case()
{



}


void capi_test::VOMS_Export_case(){}


void capi_test::VOMS_DefaultData_case(){}
