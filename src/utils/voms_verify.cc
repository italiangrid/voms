#include "sslutils.h"
#include "openssl/x509_vfy.h"
#include "openssl/x509v3.h"

#include <iostream>
#include <cstdlib>

int load_user_proxy(STACK_OF(X509) *cert_chain, const char *file) {
  int                                 ret = -1;
  BIO *                               in = NULL;
  int                                 count=0;
  X509 *                              x = NULL;

  if (file == NULL)
    return(1);

  in = BIO_new(BIO_s_file());


  if ((in == NULL) || (BIO_read_filename(in,file) <= 0))
  {
    X509err(PRXYERR_F_PROXY_LOAD, PRXYERR_R_PROCESS_PROXY);
    goto err;
  }

  for (;;)
  {
    x = PEM_read_bio_X509(in,NULL, OPENSSL_PEM_CB(NULL,NULL));
    if (x == NULL)
    {
      if ((ERR_GET_REASON(ERR_peek_error()) ==
            PEM_R_NO_START_LINE) && (count > 0))
      {
        ERR_clear_error();
        break;
      }
      else
      {
        X509err(PRXYERR_F_PROXY_LOAD, PRXYERR_R_PROCESS_PROXY);
        goto err;
      }
    }

    (void)sk_X509_insert(cert_chain,x,sk_X509_num(cert_chain));

    count++;
  }

  ret = count;

err:
  if (x != NULL)
  {
    X509_free(x);
  }

  if (in != NULL)
  {
    BIO_free(in);
  }
  return(ret);
}

int verify_cert(X509_STORE_CTX *ctx) {

  ctx->check_issued = proxy_check_issued;
  return X509_verify_cert(ctx);
}

proxy_verify_desc *setup_initializers(const char *cadir)
{
  proxy_verify_ctx_desc *pvxd = NULL;
  proxy_verify_desc *pvd = NULL;

  pvd  = (proxy_verify_desc*)      malloc(sizeof(proxy_verify_desc));
  pvxd = (proxy_verify_ctx_desc *) malloc(sizeof(proxy_verify_ctx_desc));
  pvd->cert_store = NULL;


  if (!pvd || !pvxd) {
    free(pvd);
    free(pvxd);
    return NULL;
  }

  proxy_verify_ctx_init(pvxd);
  proxy_verify_init(pvd, pvxd);

  pvd->pvxd->certdir = (char*) cadir;

  return pvd;

}

void destroy_initializers(void *data)
{
  proxy_verify_desc *pvd = (proxy_verify_desc *)data;

  if (pvd) {
    if (pvd->pvxd)
      proxy_verify_ctx_release(pvd->pvxd);

    free(pvd->pvxd);
    pvd->pvxd = NULL;
    proxy_verify_release(pvd);

    /* X509_STORE_CTX_free segfaults if passed a NULL store_ctx */
    if (pvd->cert_store)
      X509_STORE_CTX_free(pvd->cert_store);
    pvd->cert_store = NULL;

    free(pvd);
  }
}

void handle_error(const char* file, int lineno, const char* msg)
{

  fprintf(stderr, "%s:%i %s\n", file, lineno, msg);
  ERR_print_errors_fp(stderr);
  exit(-1);
}

void validation_error(){

  ERR_print_errors_fp(stderr);
  exit(1);
}

#define internal_error(msg) handle_error(__FILE__, __LINE__, msg)

void init_openssl(){

  OpenSSL_add_ssl_algorithms();
  ERR_load_proxy_error_strings();
  ERR_load_crypto_strings();

}

int main(int argc, char* argv[]){

  using namespace std; 

  const char* cert_file = NULL;
  const char* ca_dir = NULL;

  FILE *cert_fp = NULL;

  STACK_OF(X509) *cert_chain = sk_X509_new_null();
  X509* cert = NULL;

  X509_STORE *store = NULL;
  X509_STORE_CTX *ctx = NULL;
  X509_LOOKUP *lookup = NULL;

  proxy_verify_desc  *pvd = NULL; 

  if (argc != 1){
    internal_error("This program does not accept command line arguments");
  }

  init_openssl();

  if (!(cert_file = getenv("X509_USER_CERT"))){
    internal_error("Please define the X509_USER_CERT env variable pointing to the file containing the cert chain to be verified");
  }

  if (!(ca_dir = getenv("X509_CERT_DIR"))){
    internal_error("Please define the X509_CERT_DIR env variable pointing to the CA certificates directory");
  }

  if (!(cert_fp = fopen(cert_file, "r"))){
    internal_error("Error opening client certificate file");
  }

  if (load_user_proxy(cert_chain, cert_file) < 1){
    internal_error("Error loading proxy chain");
  }

  cert = sk_X509_delete(cert_chain,0);

  if (!(store = X509_STORE_new())){
    internal_error("Error creating X.509 store");
  }

  if (!X509_STORE_set_verify_cb_func(store, proxy_verify_callback)){
    internal_error("Error setting context store certificate verify callback");
  }

  if (!(lookup = X509_STORE_add_lookup(store, X509_LOOKUP_hash_dir()))){
    internal_error("Error creating store CA dir lookup");
  }

  if (!X509_LOOKUP_add_dir(lookup, ca_dir, X509_FILETYPE_PEM)){
    internal_error("Error setting ca dir lookup for X509 store");
  }

  if (!(pvd = setup_initializers(ca_dir))){
    internal_error("Error setting up proxy verification data");
  }

  if (!(ctx = X509_STORE_CTX_new())) {
    internal_error("Error creating X509_STORE_CTX object");
  }

  if (X509_STORE_CTX_init(ctx, store, cert, cert_chain) != 1) {
    internal_error("Error initializing verification context");
  }

  if (!X509_STORE_CTX_set_ex_data(ctx, PVD_STORE_EX_DATA_IDX, pvd)) {
    internal_error("Error setting pvd in verification context");
  }

#if 0
  X509_VERIFY_PARAM *param = NULL;

  if (!(param = X509_VERIFY_PARAM_new())){
    internal_error("Error allocating X509_VERIFY_PARAM struct");
  }

  if (!(X509_VERIFY_PARAM_set_purpose(param, X509_PURPOSE_ANY))) {
    internal_error("Error setting purpose on X509_VERIFY_PARAM struct");
  }

  X509_STORE_CTX_set0_param(ctx, param);
#endif

  X509_STORE_CTX_set_flags(ctx, X509_V_FLAG_ALLOW_PROXY_CERTS);

  if (verify_cert(ctx) != 1){
    validation_error();
    exit(-1);
  }

  printf("Certificate chain verified succesfully\n");

  return 0;
}
