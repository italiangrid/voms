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
#ifdef __cplusplus
}
#endif
#endif /* REPLACES_H */
