
AC_INIT([GLite Security VOMS], [1.6.20])
AC_PREREQ(2.59)
AC_CONFIG_AUX_DIR([./project])
AM_INIT_AUTOMAKE
AC_CONFIG_SRCDIR([src/utils/voms_proxy_destroy.cc])

AM_MAINTAINER_MODE

# Notices.
AC_COPYRIGHT([Copyright (c) 2004 The EU EGEE Project
See LICENCE file for details
])

#Environment.
WORKDIR=`pwd`
AC_SUBST(WORKDIR)

AM_CONDITIONAL(WANT_UNIT_TEST, test x = y)

# Checks for programs.
AC_PROG_CXX
AC_PROG_AWK
AC_PROG_CC
AC_PROG_CPP
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_MAKE_SET
AC_PROG_LIBTOOL

AC_COMPILER

# Checks for libraries.
AC_OPENSSL

# Checks for header files.
AC_HEADER_DIRENT
AC_HEADER_STDC
AC_HEADER_SYS_WAIT
AC_CHECK_HEADERS([fcntl.h libintl.h limits.h memory.h netdb.h netinet/in.h stdlib.h string.h strings.h sys/socket.h sys/time.h syslog.h termios.h unistd.h malloc.h openssl/e_os.h openssl/e_os2.h wchar.h])
AC_LANG_PUSH(C++)
AC_CHECK_HEADERS(strstream strstream.h)
AC_LANG_POP(C++)

# Checks for typedefs, structures, and compiler characteristics.
AC_HEADER_STDBOOL
AC_C_CONST
AC_TYPE_UID_T
AC_C_INLINE
AC_TYPE_OFF_T
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_CHECK_MEMBERS([struct stat.st_rdev])
AC_HEADER_TIME
AC_STRUCT_TM

# Checks for library functions.
AC_FUNC_ALLOCA
AC_FUNC_CLOSEDIR_VOID
#AC_FUNC_ERROR_AT_LINE
AC_FUNC_FORK
#AC_HEADER_MAJOR
#AC_FUNC_MALLOC
AC_FUNC_MEMCMP
#AC_FUNC_MKTIME
AC_FUNC_MMAP
#AC_FUNC_REALLOC
AC_FUNC_SETVBUF_REVERSED
#AC_TYPE_SIGNAL
#AC_FUNC_STAT
AC_FUNC_STRFTIME
#AC_FUNC_STRTOD
AC_CHECK_FUNCS([alarm atexit dup2 gethostbyaddr gethostname gethostbyname gethostname memmove memset mkfifo mktime munmap putenv select setenv sigaction socket strchr strdup strerror strndup strrchr strspn strstr strtod strtol strtoul strtoull tzset uname getpwnam])
#AC_CHECK_FUNCS([mktime lstat error strtod realloc malloc stat])

AC_REPLACE_FUNCS(getopt_long getopt_long_only daemon setenv)

# check for dependencies based on project/*m4

AC_ENABLE_GLITE([], have_glite=yes, have_glite=no) # embed AC_GLITE

AC_EXPAT([], have_expat=yes, have_expat=no)        # taken from org.glite
AC_CPPUNIT([], have_cppunit=yes, have_cppunit=no)  # taken from org.glite
AC_GLOBUS([], have_globus=yes, have_globus=no)

#AC_CHECK_FUNCS(globus_module_activate)
# check in acinclude.m4

AC_ENABLE_DOCS

AC_JAVA

TEST_USE_BSD
TEST_USE_POSIX
NEW_ISSUES
AC_DEFINE(_SVID_SOURCE, 1, [Get SVID extensions])
AC_VOMS_TIME_T_TIMEZONE
AM_WITH_DMALLOC
AC_OPENSSL_EXT_METHOD
AC_VOMS_GLOBUS_CONFIG_H
AC_VOMS_STRUCT_IOVEC
AC_VOMS_GLOBUS_OFF_T
AC_VOMS_SOCKLEN_T
AC_VOMS_FIND_FUNC
AC_VOMS_LONG_LONG
AC_VOMS_OPENSSL_EVP_MD_CTX
AC_VOMS_STRNDUP

AC_PREFIX_DEFAULT("/opt/glite")

AM_CONFIG_HEADER([src/autogen/config.h])

AC_CONFIG_FILES([Makefile
                 src/Makefile
                 src/ac/Makefile
                 src/api/Makefile
                 src/api/ccapi/Makefile
                 src/api/java/Makefile
                 src/client/Makefile
                 src/common/Makefile
                 src/include/Makefile
                 src/install/Makefile
                 src/log/Makefile
                 src/replib/Makefile
                 src/replica/Makefile
                 src/server/Makefile
                 src/socklib/Makefile
                 src/sslutils/Makefile
                 src/sslutils/oldgaa/Makefile
                 src/support/Makefile
                 src/utils/Makefile
                 doc/Makefile
                 test/Makefile
                 test/tests/Makefile
                 test/utest/Makefile])
AC_CONFIG_FILES([src/install/voms_install_db
                 src/install/voms.start
                 src/replica/voms_install_replica
                 src/install/upgrade1to2
                 src/install/mysql2oracle
                 src/support/test_setup
                 src/support/test_start
                 src/support/test_clean])
AC_OUTPUT
