# Notes on the migration of the VOMS code base to OpenSSL 1.1

This document summarizes the changes needed to migrate the VOMS code base from
OpenSSL 1.0.x to OpenSSL 1.1.y.

The changes are as focused as possible and address only the migration, with very
limited exceptions.

## Opaque data structures

One of the most important changes in the API introduced by OpenSSL 1.1 is the
introduction of opaque data types for many of the data structures.

    typedef struct x509_object_st X509_OBJECT;
    typedef struct X509_name_st X509_NAME;
    typedef struct X509_name_entry_st X509_NAME_ENTRY;
    typedef struct asn1_string_st ASN1_STRING;
    typedef struct evp_pkey_st EVP_PKEY;
    typedef struct X509_st X509;
    typedef struct X509_req_st X509_REQ;

Opaque data structures are incomplete types, with two major consequences:

1. they cannot be allocated on the stack
1. pointers to objects of those types cannot be dereferenced, e.g. to access
their fields

For what concerns the first point, the solution is to always manage explicitly
their lifetime, allocating an object on the heap and later freeing it.

For example code such as

    X509_OBJECT obj;

has to be replaced with

    X509_OBJECT* obj = X509_OBJECT_new();
    ...
    X509_OBJECT_free(obj);

The second point -- accessing the fields of the data structure -- requires the
use of getter and setter functions. The actual transformation needed for the
VOMS code are presented in the following sections.

### X509_OBJECT

Given an `X509_OBJECT* obj` that stores a CRL, in order to access the
CRL, code such as

    X509_CRL* crl = obj->data.crl;

has to be replaced with

    X509_CRL* crl = X509_OBJECT_get0_X509_CRL(obj);

### X509_NAME, X509_NAME_ENTRY, ASN1_STRING

Given `X509_NAME* name`, code such as

    int                  n     = sk_X509_NAME_ENTRY_num(name->entries)
    X509_NAME_ENTRY*     entry = sk_X509_NAME_ENTRY_value(name->entries, i);
    ASN1_STRING*         str   = entry->value;
    unsigned char const* data  = entry->value->data;
    int                  l     = entry->value->length;
    ASN1_OBJECT*         obj   = entry->object;

has to be replaced with

    int                  n     = X509_NAME_entry_count(name);
    X509_NAME_ENTRY*     entry = X509_NAME_get_entry(name, i);
    ASN1_STRING*         str   = X509_NAME_ENTRY_get_data(entry);
    unsigned char const* data  = ASN1_STRING_get0_data(str);
    int                  l     = ASN1_STRING_length(str);
    ASN1_OBJECT*         obj   = X509_NAME_ENTRY_get_object(entry);


### EVP_PKEY

Given `EVP_PKEY* key`, code such as

    RSA* rsa = key->pkey.rsa;

has to be replaced with

    RSA* rsa = EVP_PKEY_get0_RSA(key)

Code such as

    int type = key->type;
    if (type == EVP_PKEY_RSA) {

has to be replaced with 

    RSA* rsa = EVP_PKEY_get0_RSA(key)
    if (RSA) {

### X509, X509_REQ

Given `X509* cert`, to access the Message Digest

    EVP_MD const* md = EVP_get_digestbyobj(cert->sig_alg->algorithm);

has to be replaced with

    EVP_MD const* md = EVP_get_digestbynid(X509_get_signature_nid(cert));

Similarly for an `X509_REQ* req`.

Moreover there is no way to retrieve the internal X509_CINF, so code such as

    X509_CINF* cinf = cert->cert_info;

has been removed and replaced with appropriate getters and setters for the
fields of an `X509_CINF`.

Given `ASN1_INTEGER* num`, code such as

    ASN1_INTEGER_free(cert->cert_info->serialNumber);
    cert->cert_info->serialNumber = num;

has been replaced with

    X509_set_serialNumber(cert, num);
    ASN1_INTEGER_free(num);

Note how the responsibility to manage the object lifetime has
changed. `X509_set_serialNumber` in fact stores a _copy_ of `num` and
takes care of the deallocation of the previous `serialNumber`.

When the serial number is obtained from the Message Digest, the code changes
from

    unsigned char md[SHA_DIGEST_LENGTH];
    unsigned int len;
    ASN1_digest(..., md, &len);
    cert->cert_info->serialNumber = ASN1_INTEGER_new();
    cert->cert_info->serialNumber = ASN1_INTEGER_new();
    cert->cert_info->serialNumber->length = len;
    cert->cert_info->serialNumber->data   = malloc(len);
    memcpy(cert->cert_info->serialNumber->data, md, SHA_DIGEST_LENGTH);

to

    unsigned char md[SHA_DIGEST_LENGTH + 1];
    unsigned int len;
    ASN1_digest(..., md, &len);
    md[len] = '\0';
    BIGNUM* bn = NULL;
    if (BN_hex2bn(&bn, (char*)md) != 0) {
      ASN1_INTEGER* num = BN_to_ASN1_INTEGER(bn, NULL);
      BN_free(bn);
      X509_set_serialNumber(cert, num);
      ASN1_INTEGER_free(num);
    }

When the serial number is copied from another certificate, the code changes from

    ASN1_INTEGER* num = ASN1_INTEGER_dup(X509_get_serialNumber(other_cert));
    ASN1_INTEGER_free(cert->cert_info->serialNumber);
    cert->cert_info->serialNumber = num;

to

    ASN1_INTEGER* num = ASN1_INTEGER_dup(X509_get0_serialNumber(other_cert));
    X509_set_serialNumber(*new_cert, num);
    ASN1_INTEGER_free(num);

The call to ASN1\_INTEGER\_dup is needed because `X509_get0_serialNumber`
returns an `ASN1_INTEGER const*` but `X509_set_serialNumber` takes a (non-const)
`ASN1_INTEGER*`, although internally it doesn't modify
it. `X509_get_serialNumber`, which returns a non-const `ASN1_INTEGER*`, could be
used, but respecting const-correctness is preferable.

To copy the _notAfter_ attribute of a certificate from another certificate, code
such as

    X509_set_notAfter(cert, other_cert->cert_info->validity->notAfter);

has to be replaced with

    int ret = X509_set1_notAfter(cert, X509_get0_notAfter(other_cert));
 
`X509_set1_notAfter` doesn't take ownership of the argument; but
`X509_get0_notAfter` returns a non-mutable view of the internal field and
doesn't require a subsequent free.

To transfer the public key from a request to a certificate, code such as

    X509_PUBKEY_free(cert_info->key);
    cert_info->key = req->req_info->pubkey;
    req->req_info->pubkey = NULL;

has been replaced with

    EVP_PKEY* pub_key = X509_REQ_get_pubkey(req);
    X509_set_pubkey(cert, pub_key);
    EVP_PKEY_free(pub_key);

The former code was a "move" of the public key from the request to the
certificate, without any decoding. Although a function still exists to retrieve
the key material (`X509_get_X509_PUBKEY`), there is no corresponding setter.

OpenSSL 1.1 has introduced another function to retrieve the public key
from the request: `X509_REQ_get0_pubkey`. The difference between
`X509_REQ_get_pubkey` and `X509_REQ_get0_pubkey` is that the former
increments a reference count, requiring the returned `EVP_KEY` to be
subsequently freed, whereas the latter returns a "view" of the
internal public key and doesn't need to be freed. For compatibility
with OpenSSL < 1.1 however `X509_REQ_get_pubkey` is used.

The code to extract the public key from a certificate

    X509_PUBKEY *key = X509_get_X509_PUBKEY(ucert);
    EVP_PKEY* ucertpkey = X509_PUBKEY_get(key);

has been replaced with

    EVP_PKEY* ucertpkey = X509_get_pubkey(ucert);

Also in this case OpenSSL 1.1 has introduced another function to
extract the key without the need to later free it: `X509_get0_pubkey`,
but it has not been used for compatibility reasons with previous
versions of OpenSSL.

To set various attributes of the certificate, code such as

    ASN1_INTEGER_set(cert->cert_info->version, 2);
    cert->ex_flags |= EXFLAG_PROXY;
    cert->ex_pcpathlen = 0;

has to be replaced with

    X509_set_version(cert, 2L);
    X509_set_proxy_flag(cert);
    X509_set_proxy_pathlen(cert, 0);

Given `STACK_OF(X509_EXTENSION)* extensions`, to add the extensions to a
certificate, code such as

    cert->cert_info->extensions = sk_X509_EXTENSION_new_null();
    for (i = 0; i < sk_X509_EXTENSION_num(extensions); ++i) {
      X509_EXTENSION* extension = X509_EXTENSION_dup(sk_X509_EXTENSION_value(extensions, i));
      sk_X509_EXTENSION_push(cert->cert_info->extensions, extension);
    }

has to be replace with

    for (i = 0; i < sk_X509_EXTENSION_num(extensions); ++i) {
      X509_EXTENSION* extension = X509_EXTENSION_dup(sk_X509_EXTENSION_value(extensions, i));
      X509_add_ext(cert, extension, -1);
    }

Given `X509_STORE* store`, `X509_STORE_CTX* ctx` and `int
proxy_check_issued(X509_STORE_CTX*, X509*, X509*)`, code such as

    X509_STORE_CTX_init(ctx, store, ...)
    ctx->check_issued = proxy_check_issued;

has to be replaced with

    X509_STORE_set_check_issued(store, proxy_check_issued);
    X509_STORE_CTX_init(ctx, store, cert, cert_chain)

i.e. `check_issued` has to be set for the `store`, whose contents are then used
for the initialization of `ctx`.

Similarly for X505\_REQ\_INFO, code such as

    X509_REQ_INFO* req_info = req->req_info;

has been removed.

Code such as

    X509_ALGOR* alg1 = cert->cert_info->signature;
    X509_ALGOR* alg2 = cert->sig_alg;

has been replaced with

    X509_ALGOR const* alg1 = X509_get0_tbs_sigalg(cert)
    X509_ALGOR const* alg2;
    X509_get0_signature(NULL, &alg2, cert);

Code such as

    ASN1_BIT_STRING* issuerUID = issuerc->cert_info->issuerUID

has been replaced with

    ASN1_BIT_STRING const* issuerUID;
    X509_get0_uids(issuerc, &issuerUID, NULL);





### SSL_CTX

Given `SSL_CTX* ctx`, code such as

    ctx->cert_store

has to be replaced with

    SSL_CTX_get_cert_store(ctx)

### BIO

BIO has become an opaque data structure. The following lines are not
allowed any more.

    writeb = bio->method->bwrite;
    readb  = bio->method->bread;
    bio->method->bwrite = globusf_write;
    bio->method->bread  = globusf_read;

`writeb` and `readb` are global variables that are then used inside
`globus_write` and `globus_read` which wrap them in order to implement
the GSI protocol.

`bio` is created with

    bio = BIO_new_socket(newsock, BIO_NOCLOSE);
    (void)BIO_set_nbio(bio, 1);

The above code is replaced with an explicit construction of a
BIO_METHOD object, which is then properly modified and used to
construct the final BIO.

	int const biom_type = BIO_get_new_index();
	static char const* const biom_name = "VOMS I/O";
	BIO_METHOD* voms_biom = BIO_meth_new(biom_type|BIO_TYPE_SOURCE_SINK|BIO_TYPE_DESCRIPTOR, biom_name);
	
	BIO_METHOD const* sock_biom = BIO_s_socket();
	
	writeb = BIO_meth_get_write(const_cast<BIO_METHOD*>(sock_biom));
	ret = BIO_meth_set_write(voms_biom, globusf_write);
	
	readb = BIO_meth_get_read(const_cast<BIO_METHOD*>(sock_biom));
	ret = BIO_meth_set_read(voms_biom, globusf_read);

    BIO_meth_set_puts(voms_biom, BIO_meth_get_puts(const_cast<BIO_METHOD*>(sock_biom)));
    // and so on for all the other fields

The `const_cast` is needed because the BIO API (and not only that one,
in fact) is not consistently const-correct.

## Stack management

The way to declare/define a new stack of user-defined types and corresponding access functions has changed.

With OpenSSL before v. 1.1 it is necessary to declare and then define
all the functions to access a stack of a user-defined type. In VOMS
there are a couple of macros to ease the job: `DECL_STACK` is used in
a single header file to produce the declarations, `IMPL_STACK` is used
in a single source file to produce the definitions.

OpenSSL 1.1 instead offers the DEFINE_STACK_OF macro, that, given a type,
generates the data structure and all the access functions, implemented
`static inline`. This means that the macro can be used in a header
file, which can then be included whenever needed.

In order to have a common code base, the DECL_STACK and IMPL_STACK macros are always used, but when OpenSSL 1.1 is used, they are implemented as:

    #define DECL_STACK(type) DEFINE_STACK_OF(type)
    #define IMPL_STACK(type)

## Removal of macros

The macro

    #define M_ASN1_INTEGER_cmp(a,b) ASN1_STRING_cmp(\
                   (const ASN1_STRING *)a,(const ASN1_STRING *)b)

doesn't exist any more. Its use has been replaced with `ASN1_INTEGER_cmp`, not
with `ASN1_STRING_cmp`, because the name is more meaningful even if they are not
completely equivalent. For example

    if (M_ASN1_INTEGER_cmp((key->serial),
                           (X509_get0_serialNumber(iss))))

becomes

    if (ASN1_INTEGER_cmp((key->serial),
                         (X509_get0_serialNumber(iss))))


The macro

    #define M_ASN1_BIT_STRING_cmp(a,b) ASN1_STRING_cmp(\
                   (const ASN1_STRING *)a,(const ASN1_STRING *)b)

doesn't exist any more. Its use has been replaced by `ASN1_STRING_cmp`.

The macro

    /*
     * This is the default callbacks, but we can have others as well: this is
     * needed in Win32 where the application malloc and the library malloc may
     * not be the same.
     */
    #define CRYPTO_malloc_init()    CRYPTO_set_mem_functions(\
           malloc, realloc, free)

doesn't exist any more and it doesn't seem terribly useful. Removed.

The macro

    #define SSLeay_add_all_algorithms() OpenSSL_add_all_algorithms()

doesn't exist any more. Its use has been replaced by the use of
`OpenSSL_add_all_algorithms`.

The use of the macro

    # define X509_STORE_set_verify_cb_func(ctx,func) \
                X509_STORE_set_verify_cb((ctx),(func))

has been replaced by the direct call to `X509_STORE_set_verify_cb`. Moreover,
since the function returns `void`, checking the return value makes no sense.
Consequently code such as

    if (!X509_STORE_set_verify_cb_func(store, proxy_verify_callback)){
      internal_error("Error setting context store certificate verify callback");
    }

becomes

    X509_STORE_set_verify_cb(store, proxy_verify_callback);

## Encoding/decoding to/from ASN.1

The functions responsible for the encoding/decoding of user-defined
types, named `i2d_<type>`, `d2i_<type>`, `<type>_new` and
`<type>_free`, were implemented in terms of the macros `M_ASN1_I2D_*`
and `M_ASN1_D2I_*`, defined in `<openssl/asn1_mac.h>`. That header
doesn't exist any more, so those functions have been generated with
the macros `DECLARE_ASN1_FUNCTIONS`, `IMPLEMENT_ASN1_FUNCTIONS`,
`ASN1_SEQUENCE`, `ASN1_SIMPLE`, `ASN1_SEQUENCE_OF`, etc., defined in
`<openssl/asn1t.h>`.

The encoding/decoding of standard (RFC3820) Proxy Certificates is actually
available directly from OpenSSL. The encoding/decoding of pre-standard
(draft) Proxy Certificates has been adapted from the Globus code.

The encoding/decoding of Attribute Certificates and the VOMS
extensions has been re-implemented from scratch.

## Compatibility with OpenSSL 1.0.x

Many of the changes listed above involve function calls that are not
available in previous versions of OpenSSL. In order to have the same
codebase, those functions have been copied (with some adaptation) into
the VOMS code base and are conditionally enabled (see files
`ssl-compat.h` and `ssl-compat.c`).
