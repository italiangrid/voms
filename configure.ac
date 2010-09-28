AC_INIT([GLite Security VOMS], [2.0.0])
AC_PREREQ(2.57)
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

# check for dependencies based on project/*m4

AC_ENABLE_GLITE([], have_glite=yes, have_glite=no) # embed AC_GLITE

if test "x$host_cpu" = "xx86_64"; then
    AC_SUBST([libdir], ['${exec_prefix}/lib64'])
fi

if test -h /usr/lib64 ; then
    libdir='${exec_prefix}/lib'
fi

if ! test -e /usr/lib64 ; then
    libdir='${exec_prefix}/lib'
fi

AC_EXPAT([], have_expat=yes, have_expat=no)        # taken from org.glite
AC_GLOBUS([], have_globus=yes, have_globus=no)

#AC_CHECK_FUNCS(globus_module_activate)
# check in acinclude.m4

AC_JAVA
AC_ENABLE_DOCS


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
AC_CHECK_FUNCS([alarm atexit dup2 gethostbyaddr gethostname gethostbyname gethostname memmove memset mkfifo mktime munmap putenv select setenv sigaction socket strchr strdup strerror strndup strrchr strspn strstr strtod strtol strtoul strtoull tzset uname getpwnam timegm])
#AC_CHECK_FUNCS([mktime lstat error strtod realloc malloc stat])

AC_CHECK_DECLS(getopt_data)
AC_REPLACE_FUNCS(getopt_long getopt_long_only daemon setenv memset)


TEST_USE_BSD
TEST_USE_POSIX
NEW_ISSUES
AC_DEFINE(_SVID_SOURCE, 1, [Get SVID extensions])
AC_VOMS_TIME_T_TIMEZONE
AM_WITH_DMALLOC
AC_VOMS_GLOBUS_CONFIG_H
AC_VOMS_STRUCT_IOVEC
AC_VOMS_GLOBUS_OFF_T
AC_VOMS_SOCKLEN_T
AC_VOMS_FIND_FUNC
AC_VOMS_LONG_LONG
AC_VOMS_STRNDUP
AC_BUILD_API_ONLY
AC_BUILD_PARTS
AC_EMI_LIBS

GLITE_DOCBOOK_MAN

AC_LINUX
AC_TESTSUITE
PUT_PRIVATES

AC_PREFIX_DEFAULT("/opt/glite")

AM_CONFIG_HEADER([src/autogen/config.h])

if test "x$build_cpp_api" = "xyes"; then
if test "x$build_c_api" = "xyes"; then
# both C and CPP
INSTALL_API_LIBS="$WANTED_API_LIBS"
else
# CPP only
libs="$WANTED_API_LIBS"; 
lista="" ; 
for p in $libs; do 
  res=`echo $p | grep libvomsapi` ; 
  if test "x$res" == "x"; then 
	lista="$lista" ; 
  else 
	lista="$p $lista" ; 
  fi 
done ; 
INSTALL_API_LIBS="$lista"
fi
elif test "x$build_c_api" = "xyes"; then
# C only
libs="$WANTED_API_LIBS"; 
lista="" ; 
for p in $libs; do 
  res=`echo $p | grep libvomsc` ; 
  if test "x$res" == "x"; then 
	lista="$lista" ; 
  else 
	lista="$p $lista" ; 
  fi 
done ; 
INSTALL_API_LIBS="$lista"
else
# nothing
INSTALL_API_LIBS=""
fi


libs="$INSTALL_API_LIBS";
lista="" ;
for p in $libs; do
  res=`echo $p | grep _nog` ;
  if test "x$res" == "x"; then
    if test "x$build_nglobus_only" = "xyes"; then
   	  lista="$lista" ;
    else
      lista="$p $lista" ;
    fi
  else
    if test "x$build_nglobus_only" = "xyes"; then
      lista="$p $lista" ;
    elif test "x$build_emi" = "xyes"; then
   	  lista="$lista" ;
    else
      lista="$p $lista" ;
    fi
  fi
done ;
INSTALL_API_LIBS="$lista"


AC_SUBST(INSTALL_API_LIBS)

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
                 src/utils/Makefile
                 doc/Makefile
                 project/Makefile
                 testsuite/Makefile
                 testsuite/SuiteConfig])
AC_CONFIG_FILES([src/install/voms_install_db
                 src/install/voms.start
                 src/replica/voms_install_replica
                 src/install/upgrade1to2
                 src/install/mysql2oracle
                 testsuite/lib/vomssetup.exp])
AC_OUTPUT
