#include "voms_apic.h"
#include <stdio.h>
#include <openssl/bio.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/stack.h>

int main(int argc, char *argv[]) 
{
  struct vomsdata *vd = VOMS_Init(NULL, NULL);
  int error = 0;
  BIO *in = NULL;
  char *of = argv[1];
  X509 *x = NULL;
  int nid = -1;
  int index = -1;
  X509_EXTENSION *ext = NULL;

  if (vd) {
    in = BIO_new(BIO_s_file());
    if (in) {
      if (BIO_read_filename(in, of) > 0) {
        x = PEM_read_bio_X509(in, NULL, 0, NULL);
        if(!x) {
          printf("cannot read proxy:%s\n",of);
          exit(1);
        }

        nid = OBJ_txt2nid("acseq");
        index = X509_get_ext_by_NID(x, nid, -1);

        if (index >= 0) {
          ext = X509_get_ext(x, index);
    
          if (ext) {
            if (VOMS_RetrieveEXT(ext,  vd, &error)) {
              struct voms *voms = VOMS_DefaultData(vd, &error);
              
              if (voms) {
                char **fqans = voms->fqan;
                
                while (*fqans) {
                  printf("fqan: %s\n", *fqans++);
                }

                exit(0);
              }
              else {
                printf("no voms data found.");
                exit(1);
              }
            }
            else {
              printf("Error1 is: %s\n", VOMS_ErrorMessage(vd, error, NULL, 0));
              exit(1);
            }
          }
        }
        else
          printf("No extension found");
      }
    }
  }
  exit(1);
}
