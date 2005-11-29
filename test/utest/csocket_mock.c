
#include "globus_gss_assist.h"
#include <openssl/x509.h>
#include "newformat.h"

extern OM_uint32 globus_gss_assist_get_unwrap(OM_uint32 * minor_status,
					      const gss_ctx_id_t context_handle,
					      char ** data,
					      size_t * length,
					      int * token_status,
					      int (*gss_assist_get_token)(void *, void **, size_t *),
					      void * gss_assist_get_context,
					      FILE * fperr)
{
  // create an AC, encode it and send 

  InitAC();

  // need an issuer, an holder and a key

  X509 * issuer = NULL;
  BIO *in = NULL;
  in = BIO_new(BIO_s_file());
  if (BIO_read_filename(in, "issuer.pem") > 0)
    issuer = PEM_read_bio_X509(in, NULL, 0, NULL);

  if(!issuer)
    printf("Unable to find an issuer cert.");

  X509 * holder = NULL;
  in = NULL;
  in = BIO_new(BIO_s_file());
  if (BIO_read_filename(in, "holder.pem") > 0)
    holder = PEM_read_bio_X509(in, NULL, 0, NULL);

  if(!holder)
    printf("Unable to find an holder cert.");

  EVP_PKEY * key = NULL;
  in = NULL;
  in = BIO_new(BIO_s_file());
  if (BIO_read_filename(in, "key.pem") > 0)
    key = PEM_read_bio_PrivateKey(in, NULL, 0, NULL);

  X509 * ca = NULL;
  in = NULL;
  in = BIO_new(BIO_s_file());
  if (BIO_read_filename(in, "ca.pem") > 0)
    ca = PEM_read_bio_X509(in, NULL, 0, NULL);

  if(!ca)
    printf("Unable to find a ca cert.");

  // serial
  
  BIGNUM * serial = BN_value_one();
  
  // the attributes
  
  char * compact;
  compact = malloc(strlen("/testVO/Role=VO-Admin/Capability=NULL")+1);
  strcpy(compact, "/testVO/Role=VO-Admin/Capability=NULL");
  
  char * targs;
  targs = 0;

  AC * a = AC_new();
  if (!a)
    return 0;

  int res = writeac(issuer,
		    holder,
		    key,
		    serial,
		    &compact,
		    targs,
		    &a,
		    "testVO",
		    "uri",
		    600);
  
  if(!res)
    return 0;
  
  // der the AC

  length = i2d_AC(a, NULL);
  unsigned char * = (unsigned char *)OPENSSL_malloc(length);
  unsigned char * pp = p;
  unsigned char * ppp = pp;
  if(!(i2d_AC(a, &ppp)))
    return 0;
  
  // create XML output

  struct error * errs;

  



  return 1;
}
