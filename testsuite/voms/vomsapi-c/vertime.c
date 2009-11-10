#include "voms_apic.h"
#include <stdio.h>
#include <openssl/bio.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/stack.h>

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

int main(int argc, char *argv[]) 
{
  struct vomsdata *vd = VOMS_Init(NULL, NULL);
  int error = 0;
  int i = 0;
  BIO *in = NULL;
  char *of = argv[1];
  STACK_OF(X509)* chain = NULL;
  X509 *x = NULL;

  if (vd) {
    in = BIO_new(BIO_s_file());
    if (in) {
      if (BIO_read_filename(in, of) > 0) {
        x = PEM_read_bio_X509(in, NULL, 0, NULL);
        if(!x)
          exit(1);

        chain = load_chain(of);

	VOMS_SetVerificationTime(time(NULL) - 1000000, vd, &error);
        if (VOMS_Retrieve(x, chain, RECURSE_CHAIN, vd, &error)) {
	  /* Verified?  This should not be the case! */
	  exit(1);
        }
	else {
	  /* Verification failed.  This is ok. */
	  exit(0);
	}
      }
    }
  }
  exit(1);
}
