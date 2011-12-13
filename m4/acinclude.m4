AC_DEFUN([AC_LINUX],
[
    AC_MSG_CHECKING([if compiling on Linux])
    if test "x`uname -s`" = "xLinux" ; then
       AC_MSG_RESULT([yes])
       AC_DEFINE(RUN_ON_LINUX, 1, [Define to 1 if running on a Linux System])
    else
       AC_MSG_RESULT([no])
    fi
])

AC_DEFUN([AC_BUILD_PARTS],
[

  AC_ARG_WITH(all,
    [  --with-all   Enable compilation of the clients (yes)],
    [
      case "$withval" in
        yes) build_all="yes" ;;
        no)  build_all="no" ;;
        *) AC_MSG_ERROR([bad value $withval for --with-all]) ;;
      esac
    ],
    [ build_all="yes" ])

  AC_ARG_WITH(clients,
    [  --with-clients   Enable compilation of the clients (yes)],
    [
      case "$withval" in
        yes) build_clients="yes" ;;
        no)  build_clients="no" ;;
        *) AC_MSG_ERROR([bad value $withval for --with-client]) ;;
      esac
    ],
    [ build_clients="$build_all" ])

  AC_ARG_WITH(server,
    [  --with-server   Enable compilation of the server (yes)],
    [
      case "$withval" in
        yes) build_server="yes" ;;
        no)  build_server="no" ;;
        *) AC_MSG_ERROR([bad value $withval for --with-server]) ;;
      esac
    ],
    [ build_server="$build_all" ])

  AC_ARG_WITH(c-api,
    [  --with-c-api   No effect],
    [
      case "$withval" in
        yes) build_c_api="yes" ;;
        no)  build_c_api="no" ;;
        *) AC_MSG_ERROR([bad value $withval for --with-c-api]) ;;
      esac
    ],
    [ build_c_api="$build_all" ])

  AC_ARG_WITH(cpp-api,
    [  --with-cpp-api   Enable compilation of the C++ APIs (yes)],
    [
      case "$withval" in
        yes) build_cpp_api="yes" ;;
        no)  build_cpp_api="no" ;;
        *) AC_MSG_ERROR([bad value $withval for --with-cpp-api]) ;;
      esac
    ],
    [ build_cpp_api="$build_all" ])

  AC_ARG_WITH(interfaces,
    [  --with-interfaces   Enable compilation of the includes (yes)],
    [
      case "$withval" in
        yes) build_interfaces="yes" ;;
        no)  build_interfaces="no" ;;
        *) AC_MSG_ERROR([bad value $withval for --with-interfaces]) ;;
      esac
    ],
    [ build_interfaces="$build_all" ])

  AC_ARG_WITH(config,
    [  --with-config   Enable compilation of the configuration files (yes)],
    [
      case "$withval" in
        yes) build_config="yes" ;;
        no)  build_config="no" ;;
        *) AC_MSG_ERROR([bad value $withval for --with-config]) ;;
      esac
    ],
    [ build_config="$build_all" ])

  AM_CONDITIONAL(BUILD_CPP_API,    test x$build_cpp_api = xyes)
  AM_CONDITIONAL(BUILD_INTERFACES, test x$build_interfaces = xyes)
  AM_CONDITIONAL(BUILD_CLIENTS,    test x$build_clients = xyes)
  AM_CONDITIONAL(BUILD_SERVER,     test x$build_server = xyes)
  AM_CONDITIONAL(BUILD_CONFIG,     test x$build_config = xyes)
])

# AC_OPENSSL checks system openssl availability
# ---------------------------------------------
AC_DEFUN([AC_OPENSSL],
[
  AC_ARG_WITH(openssl_prefix,
              [ --with-openssl-prefix=PFX    prefix where OpenSSL is installed. (/usr)],
              [with_openssl_prefix="$withval"],
              [with_openssl_prefix=/usr])

  if test "x$with_openssl_prefix" = "x/usr" ; then
    AC_CHECK_LIB(crypto, CRYPTO_num_locks, [found=yes], [found=no])

    if test "x$found" = "xyes" ; then
	OPENSSL_LIBS="-lcrypto -lssl"
	NO_GLOBUS_FLAGS=""
    fi
  else
    SAVE_LD_LIBRARY_PATH=$LD_LIBRARY_PATH
    LD_LIBRARY_PATH="$with_openssl_prefix/lib"

    AC_LANG_PUSH(C)
    AC_CHECK_LIB(crypto, CRYPTO_num_locks, [found=yes], [found=no])
    AC_LANG_POP(C)  
    NO_GLOBUS_FLAGS="-I$with_openssl_prefix/include"

    if test "x$found" = "xyes"; then
      OPENSSL_LIBS="-L$with_openssl_prefix/lib -lcrypto -lssl"
      AC_MSG_CHECKING([for system OpenSSL version])
      cat >conftest.h <<HERE
#include <openssl/opensslv.h>
OPENSSL_VERSION_TEXT
HERE
      openssl_version=`$CPP $NO_GLOBUS_FLAGS -o - -P conftest.h`
      AC_MSG_RESULT($openssl_version)
      rm -f conftest.h
    fi
    LD_LIBRARY_PATH="$SAVE_LD_LIBRARY_PATH"
  fi

  SAVE_CFLAGS=$CFLAGS
  CFLAGS="$CFLAGS -Werror"
  AC_MSG_CHECKING(if asn1.h functions need const)
  AC_TRY_COMPILE(
	[
	#include <openssl/asn1.h>
	],
	[
	char **pp;
	long length;
	ASN1_PRINTABLESTRING *p;

	(void)M_d2i_ASN1_PRINTABLESTRING(&p, pp, length);
        ],
	[ac_need_const="no"],
	[ac_need_const="yes"])
  CFLAGS="$SAVE_CFLAGS"

  AC_MSG_RESULT($ac_need_const)

  AC_SUBST(OPENSSL_LIBS)
  AC_SUBST(NO_GLOBUS_FLAGS)

  if test "x$ac_need_const" = "xyes" ; then
    AC_DEFINE(NEEDCONST, 1, [Define to 1 if openssl needs "consted" parameters])
  fi

  AH_BOTTOM([#if defined(NEEDCONST)
#define MAYBECONST const
#else
#define MAYBECONST
#endif])
])

# AC_COMPILER add switch to enable debug and warning
# options for gcc
# -------------------------------------------------------
AC_DEFUN([AC_COMPILER],
[
    AC_ARG_WITH(debug,
      [  --with-debug Compiles without optimizations and with debug activated],
      [ac_with_debug="yes"],
      [ac_with_debug="no"])
    
    if test "x$ac_with_debug" = "xyes" ; then
      CFLAGS="-g -O0"
      CXXFLAGS="-g -O0"
    fi

    AC_ARG_WITH(warnings,
      [  --with-warnings Compiles with maximum warnings],
      [ac_with_warnings="yes"],
      [ac_with_warnings="no"])

    if test "x$ac_with_warnings" = "xyes" ; then
      CFLAGS="-g -O0 -Wall -ansi -W $CFLAGS"
      CXXFLAGS="-g -O0 -Wall -ansi -W $CXXFLAGS"
    fi
])

AC_DEFUN([AC_BUILD_API_ONLY],
[
  AC_ARG_WITH(api-only, 
    [  --with-api-only   Enable compilation of the APIs only (no)],
    [
      case "$withval" in
      yes) have_api_only="yes" ;;
      no)  have_api_only="no" ;;
      *) AC_MSG_ERROR([bad value $(withval) for --with-api-only]) ;;
      esac
    ],
    [ have_api_only="no" ])

  AM_CONDITIONAL(BUILD_ALL, test x$have_api_only = xno)
])
  

# AC_ENABLE_DOCS add switch to enable debug and warning
# options for gcc
# -------------------------------------------------------
AC_DEFUN([AC_ENABLE_DOCS],
[
    AC_ARG_ENABLE(docs,
	    [ --enable-docs Enable doc generation],
	    [
	      case "$enableval" in
	      yes) build_docs="yes" ;;
	      no) ;;
	      *) AC_MSG_ERROR(bad value $(enableval) for --enable-docs) ;;
	      esac
	    ],
	    [build_docs="no"])

    AM_CONDITIONAL(BUILD_DOCS, test x$build_docs = xyes)
])


# AC_VOMS_TIME_T_TIMEZONE test whether time_t timezone is present
# int time.h
# ------------------------------------------------------------
AC_DEFUN([AC_VOMS_TIME_T_TIMEZONE],
[
    AC_MSG_CHECKING(for time_t timezone in <time.h>)
    AC_LANG_PUSH(C)
    AC_TRY_COMPILE(
        [
        #include <time.h>
        ],
        [
        struct tm y;
        time_t offset = 3;
        time_t x = mktime(&y) + offset*60*60 - timezone;
        ],
        [ac_have_time_t_timezone="yes"],
        [ac_have_time_t_timezone="no"]
    )

    if test "X$ac_have_time_t_timezone" = "Xyes" ; then
      AC_MSG_RESULT(yes)
      AC_DEFINE(HAVE_TIME_T_TIMEZONE, 1, [Define to 1 if you have time_t timezone type in time.h])
    else
      dnl
      dnl only place this should occur is on CYGWIN B20, which has an
      dnl integer _timezone defined instead
      dnl
      AC_MSG_RESULT(no)
      AC_MSG_CHECKING(checking for time_t _timezone in <time.h>)
      AC_TRY_COMPILE(
        [
        #include <time.h>
        ],
        [
        struct tm y;
        time_t offset = 3;
        time_t x = mktime(&y) + offset*60*60 - _timezone;
        ],
        [answer=yes]
        [answer=no]
      )
   
      if test "X$answer" = "Xyes" ; then   
        AC_MSG_RESULT(yes)
        AC_DEFINE(HAVE_TIME_T__TIMEZONE, 1, [Define to 1 if you have time_t _timezone type in time.h])
      else
        AC_MSG_RESULT(no)
      fi
      AC_LANG_POP(C)
    fi
])

# AC_VOMS_STRNDUP 
# ------------------------------------------------------------
AC_DEFUN([AC_VOMS_STRNDUP],
[
    AC_MSG_CHECKING([for strndup])
    AC_TRY_LINK([
                #include <string.h>
                ], 
                [
                char *s = strndup("prova",5);
                ],
                [AC_DEFINE(HAVE_STRNDUP, 1, [Define to 1 if you have strndup in string.h])
                 AC_MSG_RESULT(yes)],
                [AC_LIBOBJ(strndup)
                AC_MSG_RESULT(no)])
])

# AC_SOCKLEN_T test whether socklen_t type is present
# ------------------------------------------------------------
AC_DEFUN([AC_VOMS_SOCKLEN_T],
[
    AC_MSG_CHECKING([for (sane) socklen_t])

    AC_TRY_COMPILE(
      [
        #include <sys/types.h> 
        #include <sys/socket.h>
      ],
      [
        socklen_t addrlen = (socklen_t)5;
        (void)getsockname(0, 0L, &addrlen); 
        return 0;
      ],
      [ac_have_socklen_t="yes"],
      [ac_have_socklen_t="no"]
    )
      
    if test "x$ac_have_socklen_t" = "xyes" ; then
      AC_DEFINE(HAVE_SOCKLEN_T, 1, [Define to 1 if you have the socklen_t type])
    fi

    AC_MSG_RESULT([$ac_have_socklen_t])
])

# AC_VOMS_FIND_FUNC
# -------------------------------------------------------------------
AC_DEFUN([AC_VOMS_FIND_FUNC],
[
    AC_MSG_CHECKING([for function name discovery])

    AC_TRY_COMPILE(
      [],
      [char *str = __func__], 
      [ac_have_func="__func__"], 
      [ac_have_func="no"]
    )

    if test "x$ac_have_func" = "xno" ; then
      AC_TRY_COMPILE(
        [],
        [char *str = __PRETTY_FUNCTION__], 
        [ac_have_func="__PRETTY_FUNCTION__"], 
        [ac_have_func="no"]
      )
    fi

    if test "x$ac_have_func" = "xno" ; then
      AC_TRY_COMPILE(
        [],
        [char *str = ___FUNCTION__], 
        [ac_have_func="__FUNCTION__"], 
        [ac_have_func="NULL"]
      )
    fi

    AC_DEFINE_UNQUOTED(FUNC_NAME, [$ac_have_func], FUNC_NAME)

    AC_MSG_RESULT([$ac_have_func])
])


AC_DEFUN([NEW_ISSUES],
[
    AC_MSG_CHECKING([for string dependency on cerr])

    AC_LANG_PUSH(C++)

    cat > conftest.cpp <<HERE
#include <string>
int main(int argc, char *argv[]) {
	std::string g;
  return 0;
}
HERE

    if ( ($CXX -c -o conftest.o conftest.cpp > /dev/null 2>&1) ); then
      if ( (nm -C conftest.o | grep cerr > /dev/null 2>&1) ); then
        AH_BOTTOM([#ifdef __cplusplus
#include <new>
#endif])
        AC_DEFINE(__THROW_BAD_ALLOC, return 0L, __THROW_BAD_ALLOC)
        AC_MSG_RESULT([yes])
      else
      AC_MSG_RESULT([no])
      fi
    else
      AC_MSG_RESULT([cannot test])
    fi

    rm -rf conftest*
    AC_LANG_POP(C++)
])

AC_DEFUN([PUT_PRIVATES],
[
        AH_BOTTOM([#if defined(__GNUC__)
#if (__GNUC__ > 3 || (__GNUC__ == 3 && __GNUC_MINOR__ >= 4))
#define UNUSED(z)  z __attribute__ ((unused))
#else
#define UNUSED(z)  z
#endif
#define PRIVATE    __attribute__ ((visibility ("hidden")))
#define PUBLIC     __attribute__ ((visibility ("default")))
#else
#define UNUSED(z)  z
#define PRIVATE
#define PUBLIC
#endif])])

        
AC_DEFUN([TEST_USE_BSD],
[
    AC_MSG_CHECKING([whether _BSD_SOURCE must be defined])

    AC_LANG_PUSH(C)
    
    cat >conftest.c <<HERE
#include <strings.h>
char *f(void)
{
  return strdup("try");
}
int main(int argc, char **argv) {
  (void)f();
  return 0;
}
HERE

    if ( ($CC -c -o conftest.o -Wall -ansi -pedantic-errors -Werror conftest.c >/dev/null 2>&1) ); then
      AC_MSG_RESULT([no])
else
  cat >conftest.c <<HERE
  #define _BSD_SOURCE
  #include <strings.h>
  char *f(void)
  {
    return strdup("try");
  }
  int main(int argc, char **argv) {
    (void)f();
    return 0;
  }
HERE
  if ( ($CC -c -o conftest.o -Wall -ansi -pedantic-errors -Werror conftest.c >/dev/null 2>&1) ); then
  AC_MSG_RESULT([Needs something else. Let's try and hope])
  else
  AC_MSG_RESULT([yes])
  AC_DEFINE(_BSD_SOURCE, 1, [needed to get ansi functions definitions])
  fi
fi
rm -rf conftest*
AC_LANG_POP(C)
])

AC_DEFUN([TEST_USE_POSIX],
[
    AC_MSG_CHECKING([wether _POSIX_SOURCE must be defined])

    AC_LANG_PUSH(C)

cat >conftest.c <<HERE
#include <stdio.h>
int f(void)
{
  return fileno(stderr);
}
int main(int argc, char **argv) {
  (void)f();
  return 0;
}
HERE
if ( ($CC -c -o conftest.o -Wall -ansi -pedantic-errors -Werror conftest.c >/dev/null 2>&1) ); then
AC_MSG_RESULT([no])
else
  cat >conftest.c <<HERE
  #define _POSIX_SOURCE
  #include <strings.h>
  int f(void)
  {
    return fileno(stderr);
  }
  int main(int argc, char **argv) {
    (void)f();
    return 0;
  }
HERE
  if ( ($CC -c -o conftest.o -Wall -ansi -pedantic-errors -Werror conftest.c >/dev/null 2>&1) ); then
  AC_MSG_RESULT([Needs something else. Let's try and hope])
  else
  AC_MSG_RESULT([yes])
  AC_DEFINE(_POSIX_SOURCE, 1, [needed to get ansi functions definitions])
  fi
fi
rm -rf conftest*
AC_LANG_POP(C)

])

AC_DEFUN([AC_TESTSUITE],
[
  AC_ARG_WITH(report-dir,
    [  --with-report-dir    Set reportdir for testsuite],
    [with_reportdir="$withval"],
    [with_reportdir="$HOME/reports"])

  AC_ARG_WITH(scratch-dir,
    [  --with-scratch-dir   Set scratchdir for testsuite],
    [with_scratchdir="$withval"],
    [with_scratchdir="/tmp"])

  AC_ARG_WITH(dbuser,
    [  --with-dbuser        Set DB user for testsuite],
    [with_dbuser="$withval"],
    [with_dbuser="root"])

  AC_ARG_WITH(dbpwd,
    [  --with-dbpwd         Set DB password for testsuite],
    [with_dbpwd="$withval"],
    [with_dbpwd=""])

  AC_ARG_WITH(mysqlconf,
    [  --with-mysqlconf     Set DB password for testsuite],
    [with_mysqlconf="$withval"],
    [with_mysqlconf=""])

  AC_ARG_ENABLE(oracle-tests,
    [  --enable-oracle-tests  Do tests against Oracle DB],
    [ case "$enableval" in
      yes) enable_oracletests="yes" ;;
      no)  enable_oracletests="no" ;;
      *) AC_MSG_ERROR([bad value $(enableval) for --enable-oracle-tests]) ;;
      esac
    ],
    [ enable_oracletests="no"])

  AC_ARG_ENABLE(mysql-tests,
    [  --enable-mysql-tests  Do tests against MySQL DB],
    [ case "$enableval" in
      yes) enable_mysqltests="yes" ;;
      no)  enable_mysqltests="no" ;;
      *) AC_MSG_ERROR([bad value $(enableval) for --enable-mysql-tests]) ;;
      esac
    ],
    [ enable_mysqltests="yes"])

  AC_ARG_ENABLE(coverage,
    [  --enable-coverage Enable getting coverage info on the testsuite execution],
    [
      case "$enableval" in
      yes) enable_coverage="yes" ;;
      no)  enable_coverage="no" ;;
      *)   AC_MSG_ERROR([bad value $(enableval) for --enable-coverage]) ;;
      esac
    ],
    [ enable_coverage="no" ])

  if test "x$enable_coverage" = "xyes" ; then
     CFLAGS="$CFLAGS -fprofile-arcs -ftest-coverage"
     CXXFLAGS="$CXXFLAGS -fprofile-arcs -ftest-coverage"
     LDFLAGS="$LDFLAGS -lgcov"
  fi

  AC_ARG_WITH(cobertura,
	      [ --with-cobertura=PFX    prefix where cobertura is placed (no default)],
	      [with_cobertura_prefix="$withval"],
	      [with_cobertura_prefix="no"])

  AC_ARG_WITH(valgrind,
        [ --with-valgrind=PFX     Also test memory leaks with valgrind],
        [with_valgrind="$withval"],
        [with_valgrind="no"])

  echo "with_valgrind=$with_valgrind"
  if test "x$with_valgrind" == "x" ; then
     with_valgrind=`which valgrind` 2>/dev/null;
  fi
  echo "with_valgrind=$with_valgrind"
  if test "x$with_valgrind" == "xno" ; then
     with_valgrind="";
  fi
  echo "with_valgrind=$with_valgrind"

  AM_CONDITIONAL(USE_COBERTURA, test ! x$with_cobertura_prefix = xno)
  AC_SUBST(with_valgrind)
  AC_SUBST(with_reportdir)
  AC_SUBST(with_scratchdir)
  AC_SUBST(with_dbuser)
  AC_SUBST(with_dbpwd)
  AC_SUBST(with_mysqlconf)
  AC_SUBST(enable_oracletests)
  AC_SUBST(enable_mysqltests)
  AC_SUBST(enable_coverage)
  AC_SUBST(with_cobertura_prefix)
])

dnl This macro written by:
dnl author: Gabor Gombas.
dnl
dnl
dnl GLITE_DOCBOOK_HTML
dnl
dnl Check for xsltproc and the HTML stylesheets
dnl
AC_DEFUN([GLITE_DOCBOOK_MAN], [
	AC_PATH_PROG([XSLTPROC], [xsltproc], [no])
	if test "$XSLTPROC" != no; then
		if test -z "$XLSTPROCFLAGS"; then
			XSLTPROCFLAGS="--nonet"
		fi
		AC_CACHE_CHECK([for DocBook XML manpage stylesheets], [glite_cv_docbook_man],
		[
			cat >conftest.xml <<"EOF"
<?xml version="1.0"?>
	<!-- "http://www.oasis-open.org/docbook/xml/4.1.2/docbookx.dtd" @<:@ -->
<?xml-stylesheet href="http://docbook.sourceforge.net/release/xsl/current/manpages/docbook.xsl" type="text/xsl"?>
<!DOCTYPE refentry PUBLIC "-//OASIS//DTD DocBook XML V4.1.2//EN"
	"http://www.oasis-open.org/docbook/xml/4.1.2/docbookx.dtd" @<:@
@:>@>
<refentry id="test">
<refmeta>
    <refentrytitle>TEST</refentrytitle>
    <manvolnum>test</manvolnum>
</refmeta>
</refentry>
EOF
			$XSLTPROC $XSLTPROCFLAGS http://docbook.sourceforge.net/release/xsl/current/manpages/docbook.xsl conftest.xml >/dev/null 2>/dev/null
			result=$?
			if test $result = 0; then
				glite_cv_docbook_man=yes
			else
				glite_cv_docbook_man=no
			fi
		])
		AC_SUBST([XSLTPROCFLAGS])
	fi
	AM_CONDITIONAL([HAVE_DOCBOOK_MAN], [test "$glite_cv_docbook_man" = yes])
])

AC_DEFUN([AC_VOMS_LOCATIONS],
[
	AC_SUBST(LOCATION_ENV, "VOMS_LOCATION")
	AC_DEFINE(LOCATION_ENV, "VOMS_LOCATION", "Name of the voms location environment variable")
	AC_DEFINE(LOCATION_DIR, "/usr", "Location of the system directory")
	AC_SUBST(LOCATION_DIR, "/usr")
	AC_DEFINE(USER_DIR, ".voms", [VOMS user preferences directory])
])	
