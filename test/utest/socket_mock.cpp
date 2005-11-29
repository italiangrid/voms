
/** This class header file. */
#include "Client.h"
/** The tokens transission and reception features definitions. */
#include "tokens.h"


#include "ccwrite.h"
#include "newformat.h"
#include "format.h"

#include "vomsxml.h"

#include <openssl/pem.h>

#include<iostream>

extern int AC_Init(void);

GSISocketClient::GSISocketClient(const std::string h, int p, int v, void *l) : own_subject("f")
{
}

GSISocketClient::~GSISocketClient()
{
}

void 
GSISocketClient::SetFlags(OM_uint32 f)
{
}

void GSISocketClient::SetLogger(void *l)
{
}

bool 
GSISocketClient::InitGSIAuthentication(int sock)
{
  return true;
}

bool 
GSISocketClient::Open()
{
  return true;
}

void
GSISocketClient::Close()
{
}

bool 
GSISocketClient::Send(const std::string s)
{
  return true;
}

bool GSISocketClient::Receive(std::string& s)
{
  // create an AC, encode it and send 

  AC_Init();

  // need an issuer, an holder and a key

  std::string issuer_cert = "issuer.pem";
  X509 * issuer = NULL;
  BIO *in = NULL;
  in = BIO_new(BIO_s_file());
  if (BIO_read_filename(in, issuer_cert.c_str()) > 0)
    issuer = PEM_read_bio_X509(in, NULL, 0, NULL);
  if(!issuer)
    std::cout << "Unable to find an issuer cert."<< std::endl;

  std::string holder_cert = "holder.pem";
  X509 * holder = NULL;
  in = NULL;
  in = BIO_new(BIO_s_file());
  if (BIO_read_filename(in, holder_cert.c_str()) > 0)
    holder = PEM_read_bio_X509(in, NULL, 0, NULL);
  if(!holder)
    std::cout << "Unable to find an holder cert."<< std::endl;

  std::string issuer_key = "key.pem";
  EVP_PKEY * key = NULL;
  in = NULL;
  in = BIO_new(BIO_s_file());
  if (BIO_read_filename(in, issuer_key.c_str()) > 0)
    key = PEM_read_bio_PrivateKey(in, NULL, 0, NULL);

  std::string ca_cert = "ca.pem";
  X509 * ca = NULL;
  in = NULL;
  in = BIO_new(BIO_s_file());
  if (BIO_read_filename(in, ca_cert.c_str()) > 0)
    ca = PEM_read_bio_X509(in, NULL, 0, NULL);
  if(!ca)
    std::cout << "Unable to find a ca cert."<< std::endl;

  // serial
  
  BIGNUM * serial = BN_value_one();
  
  // the attributes
  
  std::vector<std::string> compact;
  compact.push_back(std::string("/testVO/Role=VO-Admin/Capability=NULL"));
  
  // other stuff

  std::vector<std::string> targs;

  AC * a = AC_new();
  if (!a)
    return false;

  int res = createac(issuer,
		     holder,
		     key,
		     serial,
		     compact,
		     targs,
		     &a,
		     "testVO",
		     "uri",
		     600,
		     true);
  
  if(!res)
    return false;
  
  // der the AC

  unsigned int len = i2d_AC(a, NULL);
  unsigned char * p = (unsigned char *)OPENSSL_malloc(len);
  unsigned char * pp = p;
  unsigned char * ppp = pp;
  if(!(i2d_AC(a, &ppp)))
    return false;
  
  // create XML output

  std::string codedac = std::string((char *)pp, len);
  std::vector<errorp> errs;
  
  std::string ret = XML_Ans_Encode(codedac, 
				   errs);
  
  s = std::string(ret);
  
  return true;
}

std::string  
GSISocketClient::GetError()
{
  return "";
}
