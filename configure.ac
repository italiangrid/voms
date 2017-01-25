AC_INIT([VOMS], [2.1.0])
AC_PREREQ(2.57)
AC_CONFIG_AUX_DIR([./aux])
AM_INIT_AUTOMAKE
AC_CONFIG_SRCDIR([src/utils/voms_proxy_destroy.cc])
AC_CONFIG_MACRO_DIR([m4])
AM_MAINTAINER_MODE

AC_PREFIX_DEFAULT("/")

# Notices.
AC_COPYRIGHT([Copyright (c) 2004-2012 Istituto Nazionale di Fisica Nucleare 
See LICENCE file for details
])

#Environment.
WORKDIR=`pwd`
AC_SUBST(WORKDIR)

# Checks for programs.
AC_PROG_CXX
AC_PROG_AWK
AC_PROG_CC
AM_PROG_CC_C_O
AC_PROG_CPP
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_MAKE_SET
AC_PROG_LIBTOOL
AC_PROG_YACC
AC_PROG_LEX
AC_COMPILER

PKG_CHECK_MODULES([OPENSSL], [openssl])
# AC_OPENSSL

PKG_CHECK_MODULES([GSOAP],[gsoap >= 2.7])
PKG_CHECK_MODULES([GSOAP_PP],[gsoap++ >= 2.7])
PKG_CHECK_MODULES([GSOAP_SSL],[gsoapssl >= 2.7])
PKG_CHECK_MODULES([GSOAP_SSL_PP],[gsoapssl++ >= 2.7])

AC_CHECK_HEADER([expat.h], 
    [], 
    [AC_MSG_ERROR("Could not find expat.h. Please install the expat development package.")],
    [])

AC_CHECK_LIB([expat],
    [XML_ParserCreate],
    [EXPAT_LIBS=-lexpat],
    [AC_MSG_ERROR("Error checking libexpat. Please install the expat development package.")]
    )

AC_SUBST(EXPAT_LIBS)

AC_WSDL2H
AC_ENABLE_DOCS

# Checks for header files.
AC_HEADER_DIRENT
AC_HEADER_STDC
AC_HEADER_SYS_WAIT
AC_CHECK_HEADERS([fcntl.h libintl.h limits.h memory.h netdb.h netinet/in.h stdlib.h string.h strings.h sys/socket.h sys/time.h syslog.h termios.h unistd.h malloc.h wchar.h])

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
AC_FUNC_FORK
AC_FUNC_MEMCMP
AC_FUNC_MMAP
AC_FUNC_SETVBUF_REVERSED
AC_FUNC_STRFTIME
AC_CHECK_FUNCS([alarm atexit dup2 gethostbyaddr gethostname gethostbyname gethostname memmove memset mkfifo mktime munmap putenv select setenv sigaction socket strchr strdup strerror strndup strrchr strspn strstr strtod strtol strtoul strtoull tzset uname getpwnam timegm])

AC_CHECK_DECLS(getopt_data)
AC_REPLACE_FUNCS(getopt_long getopt_long_only daemon setenv memset)

TEST_USE_BSD
TEST_USE_POSIX

# NEW_ISSUES

AC_DEFINE(_SVID_SOURCE, 1, [Get SVID extensions])
AC_VOMS_TIME_T_TIMEZONE
AM_WITH_DMALLOC

AC_VOMS_SOCKLEN_T
AC_VOMS_FIND_FUNC
AC_VOMS_STRNDUP

AC_BUILD_API_ONLY
AC_BUILD_PARTS
GLITE_DOCBOOK_MAN

AC_LINUX
AC_TESTSUITE
PUT_PRIVATES

AC_VOMS_LOCATIONS

AC_ARG_WITH(vomsuser,
  [  --with-vomsuser=USR    Sets the user used to run voms],
  [with_vomsuser="$withval"],
  [with_vomsuser="voms"]
)
  
AC_SUBST(with_vomsuser)
AC_PARSER_GEN

AC_CONFIG_HEADERS([src/autogen/config.h])

if test "x$build_cpp_api" = "xyes" -o "x$build_interfaces" = "xyes"; then
# both C and CPP
INSTALL_API_LIBS="libvomsapi.la"
else
INSTALL_API_LIBS=""
fi


AC_SUBST(INSTALL_API_LIBS)

AC_CONFIG_FILES([Makefile
                 src/Makefile
                 src/ac/Makefile
                 src/api/Makefile
                 src/api/ccapi/Makefile
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
                 src/utils/Makefile
                 doc/Makefile
                 m4/Makefile
                 testsuite/Makefile
                 testsuite/SuiteConfig])
                 
AC_CONFIG_FILES([src/install/voms_install_db
                 src/install/voms.start
                 src/replica/voms_install_replica
                 src/install/upgrade1to2
                 src/install/mysql2oracle
                 src/install/sysconfig-voms
                 src/api/ccapi/voms-2.0.pc])
AC_OUTPUT
