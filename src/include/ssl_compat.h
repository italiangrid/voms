#include <openssl/opensslv.h>

#if OPENSSL_VERSION_NUMBER < 0x10100000L

#include <openssl/bio.h>
#include <openssl/x509.h>
#include <inttypes.h>

#ifdef __cplusplus
extern "C" {
#endif

const unsigned char *ASN1_STRING_get0_data(const ASN1_STRING *x);
struct rsa_st *EVP_PKEY_get0_RSA(EVP_PKEY *pkey);
int X509_REQ_get_signature_nid(const X509_REQ *req);
const ASN1_INTEGER *X509_get0_serialNumber(const X509 *x);
int X509_set1_notAfter(X509 *x, const ASN1_TIME *tm);
const ASN1_TIME *X509_get0_notAfter(const X509 *x);
void X509_set_proxy_flag(X509 *x);
void X509_set_proxy_pathlen(X509 *x, long l);
X509 *X509_STORE_CTX_get0_cert(X509_STORE_CTX *ctx);
X509_OBJECT *X509_OBJECT_new(void);
X509_CRL *X509_OBJECT_get0_X509_CRL(X509_OBJECT *a);
const ASN1_TIME *X509_CRL_get0_nextUpdate(const X509_CRL *crl);
const ASN1_INTEGER *X509_REVOKED_get0_serialNumber(const X509_REVOKED *x);
STACK_OF(X509) *X509_STORE_CTX_get0_chain(X509_STORE_CTX *ctx);
long X509_get_proxy_pathlen(X509 *x);
uint32_t X509_get_extension_flags(X509 *x);
void X509_STORE_CTX_set_current_cert(X509_STORE_CTX *ctx, X509 *x);
void X509_OBJECT_free(X509_OBJECT *a);
typedef int (*X509_STORE_CTX_check_issued_fn)(X509_STORE_CTX *ctx,
                                              X509 *x, X509 *issuer);
void X509_STORE_set_check_issued(X509_STORE *ctx,
                                 X509_STORE_CTX_check_issued_fn check_issued);
void RSA_get0_factors(const RSA *r, const BIGNUM **p, const BIGNUM **q);
void RSA_get0_key(const RSA *r,
                  const BIGNUM **n, const BIGNUM **e, const BIGNUM **d);
int RSA_set0_key(RSA *r, BIGNUM *n, BIGNUM *e, BIGNUM *d);
const STACK_OF(X509_EXTENSION) *X509_get0_extensions(const X509 *x);
const X509_ALGOR *X509_get0_tbs_sigalg(const X509 *x);
void X509_get0_uids(const X509 *x, const ASN1_BIT_STRING **piuid,
                    const ASN1_BIT_STRING **psuid);
int BIO_get_new_index(void);
BIO_METHOD *BIO_meth_new(int type, const char *name);
int (*BIO_meth_get_write(BIO_METHOD *biom)) (BIO *, const char *, int);
int BIO_meth_set_write(BIO_METHOD *biom, int (*write) (BIO *, const char *, int));
int (*BIO_meth_get_read(BIO_METHOD *biom)) (BIO *, char *, int);
int BIO_meth_set_read(BIO_METHOD *biom, int (*read) (BIO *, char *, int));
int (*BIO_meth_get_puts(BIO_METHOD *biom)) (BIO *, const char *);
int BIO_meth_set_puts(BIO_METHOD *biom, int (*puts) (BIO *, const char *));
int (*BIO_meth_get_gets(BIO_METHOD *biom)) (BIO *, char *, int);
int BIO_meth_set_gets(BIO_METHOD *biom, int (*gets) (BIO *, char *, int));
long (*BIO_meth_get_ctrl(BIO_METHOD *biom)) (BIO *, int, long, void *);
int BIO_meth_set_ctrl(BIO_METHOD *biom, long (*ctrl) (BIO *, int, long, void *));
int (*BIO_meth_get_create(BIO_METHOD *bion)) (BIO *);
int BIO_meth_set_create(BIO_METHOD *biom, int (*create) (BIO *));
int (*BIO_meth_get_destroy(BIO_METHOD *biom)) (BIO *);
int BIO_meth_set_destroy(BIO_METHOD *biom, int (*destroy) (BIO *));
long (*BIO_meth_get_callback_ctrl(BIO_METHOD *biom))(BIO *, int, bio_info_cb *);
int BIO_meth_set_callback_ctrl(BIO_METHOD *biom, long (*callback_ctrl) (BIO *, int, bio_info_cb *));

#if OPENSSL_VERSION_NUMBER < 0x10002000L

int X509_get_signature_nid(const X509 *x);
void X509_get0_signature(const ASN1_BIT_STRING **psig,
                         const X509_ALGOR **palg, const X509 *x);

#endif

#ifdef __cplusplus
}
#endif

#endif
