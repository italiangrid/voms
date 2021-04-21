#include "ssl_compat.h"

#if OPENSSL_VERSION_NUMBER < 0x10100000L

#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <string.h>

#define X509_F_X509_PUBKEY_GET0                          119
#define EVP_F_EVP_PKEY_GET0_RSA                          121
#define X509_F_X509_PUBKEY_DECODE                        148
#define X509_F_X509_OBJECT_NEW                           150

static void *CRYPTO_zalloc(size_t num, const char *file, int line)
{
  void *ret = CRYPTO_malloc(num, file, line);

  if (ret != NULL)
    memset(ret, 0, num);
  return ret;
}

#define OPENSSL_zalloc(num) CRYPTO_zalloc(num, __FILE__, __LINE__)

const unsigned char *ASN1_STRING_get0_data(const ASN1_STRING *x)
{
  return x->data;
}

struct rsa_st *EVP_PKEY_get0_RSA(EVP_PKEY *pkey)
{
  if (pkey->type != EVP_PKEY_RSA) {
    EVPerr(EVP_F_EVP_PKEY_GET0_RSA, EVP_R_EXPECTING_AN_RSA_KEY);
    return NULL;
  }
  return pkey->pkey.rsa;
}

int X509_REQ_get_signature_nid(const X509_REQ *req)
{
  return OBJ_obj2nid(req->sig_alg->algorithm);
}

const ASN1_INTEGER *X509_get0_serialNumber(const X509 *x)
{
  return x->cert_info->serialNumber;
}

static int x509_set1_time(ASN1_TIME **ptm, const ASN1_TIME *tm)
{
  ASN1_TIME *in;
  in = *ptm;
  if (in != tm) {
    in = ASN1_STRING_dup(tm);
    if (in != NULL) {
      ASN1_TIME_free(*ptm);
      *ptm = in;
    }
  }
  return (in != NULL);
}

int X509_set1_notAfter(X509 *x, const ASN1_TIME *tm)
{
  if (x == NULL)
    return 0;
  return x509_set1_time(&x->cert_info->validity->notAfter, tm);
}

const ASN1_TIME *X509_get0_notAfter(const X509 *x)
{
  return x->cert_info->validity->notAfter;
}

void X509_set_proxy_flag(X509 *x)
{
  x->ex_flags |= EXFLAG_PROXY;
}

void X509_set_proxy_pathlen(X509 *x, long l)
{
  x->ex_pcpathlen = l;
}

X509 *X509_STORE_CTX_get0_cert(X509_STORE_CTX *ctx)
{
  return ctx->cert;
}

#define X509_LU_NONE 0

X509_OBJECT *X509_OBJECT_new(void)
{
  X509_OBJECT *ret = OPENSSL_zalloc(sizeof(*ret));

  if (ret == NULL) {
    X509err(X509_F_X509_OBJECT_NEW, ERR_R_MALLOC_FAILURE);
    return NULL;
  }
  ret->type = X509_LU_NONE;
  return ret;
}

X509_CRL *X509_OBJECT_get0_X509_CRL(X509_OBJECT *a)
{
  if (a == NULL || a->type != X509_LU_CRL)
    return NULL;
  return a->data.crl;
}

const ASN1_TIME *X509_CRL_get0_nextUpdate(const X509_CRL *crl)
{
  return crl->crl->nextUpdate;
}

const ASN1_INTEGER *X509_REVOKED_get0_serialNumber(const X509_REVOKED *x)
{
  return x->serialNumber;
}

STACK_OF(X509) *X509_STORE_CTX_get0_chain(X509_STORE_CTX *ctx)
{
  return ctx->chain;
}

long X509_get_proxy_pathlen(X509 *x)
{
  /* Called for side effect of caching extensions */
  if (X509_check_purpose(x, -1, -1) != 1
      || (x->ex_flags & EXFLAG_PROXY) == 0)
    return -1;
  return x->ex_pcpathlen;
}

uint32_t X509_get_extension_flags(X509 *x)
{
  /* Call for side-effect of computing hash and caching extensions */
  X509_check_purpose(x, -1, -1);
  return x->ex_flags;
}

void X509_STORE_CTX_set_current_cert(X509_STORE_CTX *ctx, X509 *x)
{
  ctx->current_cert = x;
}

void X509_OBJECT_free(X509_OBJECT *a)
{
  if (a == NULL)
    return;
  switch (a->type) {
    default:
      break;
    case X509_LU_X509:
      X509_free(a->data.x509);
      break;
    case X509_LU_CRL:
      X509_CRL_free(a->data.crl);
      break;
  }
  OPENSSL_free(a);
}

void X509_STORE_set_check_issued(X509_STORE *ctx,
                                 X509_STORE_CTX_check_issued_fn check_issued)
{
  ctx->check_issued = check_issued;
}

void RSA_get0_factors(const RSA *r, const BIGNUM **p, const BIGNUM **q)
{
  if (p != NULL)
    *p = r->p;
  if (q != NULL)
    *q = r->q;
}

void RSA_get0_key(const RSA *r,
                  const BIGNUM **n, const BIGNUM **e, const BIGNUM **d)
{
  if (n != NULL)
    *n = r->n;
  if (e != NULL)
    *e = r->e;
  if (d != NULL)
    *d = r->d;
}

int RSA_set0_key(RSA *r, BIGNUM *n, BIGNUM *e, BIGNUM *d)
{
  /* If the fields n and e in r are NULL, the corresponding input
   * parameters MUST be non-NULL for n and e.  d may be
   * left NULL (in case only the public key is used).
   */
  if ((r->n == NULL && n == NULL)
      || (r->e == NULL && e == NULL))
    return 0;

  if (n != NULL) {
    BN_free(r->n);
    r->n = n;
  }
  if (e != NULL) {
    BN_free(r->e);
    r->e = e;
  }
  if (d != NULL) {
    BN_free(r->d);
    r->d = d;
  }

  return 1;
}

const STACK_OF(X509_EXTENSION) *X509_get0_extensions(const X509 *x)
{
  return x->cert_info->extensions;
}

const X509_ALGOR *X509_get0_tbs_sigalg(const X509 *x)
{
    return x->cert_info->signature;
}

void X509_get0_uids(const X509 *x, const ASN1_BIT_STRING **piuid,
                    const ASN1_BIT_STRING **psuid)
{
    if (piuid != NULL)
        *piuid = x->cert_info->issuerUID;
    if (psuid != NULL)
        *psuid = x->cert_info->subjectUID;
}

#define BIO_TYPE_START           128

int BIO_get_new_index(void)
{
  static int bio_count = BIO_TYPE_START;

  /* not thread-safe */
  return ++bio_count;
}

BIO_METHOD *BIO_meth_new(int type, const char *name)
{
  BIO_METHOD *biom = OPENSSL_zalloc(sizeof(BIO_METHOD));

  if (biom != NULL) {
    biom->type = type;
    biom->name = name;
  }
  return biom;
}

int (*BIO_meth_get_write(BIO_METHOD *biom)) (BIO *, const char *, int)
{
  return biom->bwrite;
}

int BIO_meth_set_write(BIO_METHOD *biom, int (*bwrite) (BIO *, const char *, int))
{
  biom->bwrite = bwrite;
  return 1;
}

int (*BIO_meth_get_read(BIO_METHOD *biom)) (BIO *, char *, int)
{
  return biom->bread;
}

int BIO_meth_set_read(BIO_METHOD *biom, int (*bread) (BIO *, char *, int))
{
  biom->bread = bread;
  return 1;
}

int (*BIO_meth_get_puts(BIO_METHOD *biom)) (BIO *, const char *)
{
  return biom->bputs;
}

int BIO_meth_set_puts(BIO_METHOD *biom,
                      int (*bputs) (BIO *, const char *))
{
  biom->bputs = bputs;
  return 1;
}

int (*BIO_meth_get_gets(BIO_METHOD *biom)) (BIO *, char *, int)
{
  return biom->bgets;
}

int BIO_meth_set_gets(BIO_METHOD *biom, int (*bgets) (BIO *, char *, int))
{
  biom->bgets = bgets;
  return 1;
}

long (*BIO_meth_get_ctrl(BIO_METHOD *biom)) (BIO *, int, long, void *)
{
  return biom->ctrl;
}

int BIO_meth_set_ctrl(BIO_METHOD *biom, long (*ctrl) (BIO *, int, long, void *))
{
  biom->ctrl = ctrl;
  return 1;
}

int (*BIO_meth_get_create(BIO_METHOD *biom)) (BIO *)
{
  return biom->create;
}

int BIO_meth_set_create(BIO_METHOD *biom, int (*create) (BIO *))
{
  biom->create = create;
  return 1;
}

int (*BIO_meth_get_destroy(BIO_METHOD *biom)) (BIO *)
{
  return biom->destroy;
}

int BIO_meth_set_destroy(BIO_METHOD *biom, int (*destroy) (BIO *))
{
  biom->destroy = destroy;
  return 1;
}

long (*BIO_meth_get_callback_ctrl(BIO_METHOD *biom)) (BIO *, int, bio_info_cb *)
{
  return biom->callback_ctrl;
}

int BIO_meth_set_callback_ctrl(BIO_METHOD *biom, long (*callback_ctrl) (BIO *, int, bio_info_cb *))
{
  biom->callback_ctrl = callback_ctrl;
  return 1;
}

#if OPENSSL_VERSION_NUMBER < 0x10002000L

int X509_get_signature_nid(const X509 *x)
{
  return OBJ_obj2nid(x->sig_alg->algorithm);
}

void X509_get0_signature(const ASN1_BIT_STRING **psig,
                         const X509_ALGOR **palg, const X509 *x)
{
  if (psig)
    *psig = x->signature;
  if (palg)
    *palg = x->sig_alg;
}

#endif

#endif
