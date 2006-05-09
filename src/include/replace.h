#ifndef VOMS_REPLACES_H
#define VOMS_REPLACES_H
#include "config.h"

#ifndef HAVE_GLOBUS_OFF_T
#ifdef HAVE_LONG_LONG_T
#define GLOBUS_OFF_T long long
#else
#define GLOBUS_OFF_T long
#endif
#endif

#ifdef __cplusplus
extern "C" {
#endif
#ifndef HAVE_DAEMON
extern int daemon(int, int);
#endif
#ifndef HAVE_SETENV
extern int setenv(const char *, const char *, int);
extern void unsetenv(const char *);
#endif
#ifndef HAVE_STRNDUP
#include <string.h>
extern char *strndup(const char *, size_t);
#endif
#ifndef NOGLOBUS
#ifndef HAVE_EVP_MD_CTX_INIT
#define EVP_MD_CTX_init
#endif
#ifndef HAVE_EVP_MD_CTX_CLEANUP
#define EVP_MD_CTX_cleanup
#endif
#else
#ifndef HAVE_EVP_MD_CTX_INIT_OPENSSL
#define EVP_MD_CTX_init
#endif
#ifndef HAVE_EVP_MD_CTX_CLEANUP_OPENSSL
#define EVP_MD_CTX_cleanup
#endif
#endif
#ifdef __cplusplus
}
#endif
#endif /* REPLACES_H */
