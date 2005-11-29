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
#include "../include/config.h"

#include <stdio.h>
#include <voms_apic.h>

#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/x509.h>
#include <openssl/bn.h>
#include <openssl/asn1.h>

#include "write.h"
#include "newformat.h"
#include "init.h"
#include "extensions.h"
#include "validate.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

int main(int argc, char *argv[])
{
  int res;
  BIO *in = NULL;
  BIO *in2 = NULL;
  BIO *in3 = NULL;
  BIO *out;
  X509 *i = NULL, *h = NULL;
  EVP_PKEY *k = NULL;
  AC *value = AC_new();
  int len = 0;
  unsigned char *buffer, *p, *tmp, *tmp2, *tmp3;
  int fd = 0;
  int sum=0,cur;
  AC this;
  AC *newval = &this;

  char *c[3]= {"cap1", "cap2", NULL};
  struct col v;

  declareOIDs();
  (void)initEx();

  in = BIO_new(BIO_s_file());
  in2 = BIO_new(BIO_s_file());
  in3 = BIO_new(BIO_s_file());
  out = BIO_new(BIO_s_file());

  BIO_write_filename(out, "outca");

  if (BIO_read_filename(in, "holder") > 0)
    h = PEM_read_bio_X509(in, NULL, 0, NULL);

  if (BIO_read_filename(in2, "issuer") > 0)
    i = PEM_read_bio_X509(in2, NULL, 0, NULL);

  if (BIO_read_filename(in3, "key") > 0)
    k = PEM_read_bio_PrivateKey(in3, NULL, NULL, NULL);

  res = writeac(i, h, k, (BIGNUM *)(BN_value_one()), c, "group1, datatag6", &value, "WPtest", "datatag6.cnaf.infn.it:50000", 1);

  len = i2d_AC(value,0);
  fprintf(stderr, "len = %d\n",len);
  tmp3 = p = buffer = (unsigned char *)OPENSSL_malloc((unsigned int)len);
  i2d_AC(value, &p);

  fd = open("ac", O_CREAT | O_WRONLY | O_TRUNC);
  write(fd, tmp3, len);
  close(fd);

  newval=d2i_AC(NULL,&buffer,len);
  printf("%d\n",validate(h,i,newval, &v, 0));
  ERR_print_errors_fp(stderr);
  tmp = tmp2 = (unsigned char *)OPENSSL_malloc((unsigned int)len);
  i2d_AC(newval, &tmp);

  if (memcmp(tmp3, tmp2, len) == 0)
    printf("OK!\n");
  else
    printf("NO!\n");

  PEM_ASN1_write_bio(i2d_AC, "ATTRIBUTE CERTIFICATE", out, (char *)value, NULL,NULL,0,NULL, NULL);

  OPENSSL_free(tmp3);
  OPENSSL_free(tmp2);
  BIO_free(in);
  BIO_free(in2);
  BIO_free(in3);
  BIO_free(out);
  X509_free(i);
  X509_free(h);
  EVP_PKEY_free(k);
  AC_free(value);
  AC_free(newval);
}
