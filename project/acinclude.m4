
# AC_GLOBUS checks globus prefix, looks for globus 
# flavors, selects globus flavor and define wanted lib
# according to flavor installed with their own compiler
# flags 
# -------------------------------------------------------
AC_DEFUN([AC_GLOBUS],
[
    AC_ARG_WITH(globus_prefix,
	[  --with-globus-prefix=PFX     prefix where GLOBUS is installed. (/opt/globus)],
	[],
        [with_globus_prefix=${GLOBUS_LOCATION:-/opt/globus}])

    AC_MSG_CHECKING([for GLOBUS installation at $with_globus_prefix])
    # to be added
    AC_MSG_RESULT([yes])

    LD_LIBRARY_PATH="$LD_LIBRARY_PATH:$with_globus_prefix/lib"
    AC_MSG_CHECKING([for GLOBUS flavors])

    for i in `ls $with_globus_prefix/include`; do
      GLOBUS_FLAVORS="$GLOBUS_FLAVORS $i"
    done

    if test -e $with_globus_prefix/include/gcc32dbg ; then
      default_flavor=gcc32dbg
    elif test -e $with_globus_prefix/include/gcc64dbg ; then
      default_flavor=gcc64dbg
    else
      default_flavor=""
    fi

    AC_ARG_WITH(globus_flavor,
              	[  --with-globus-flavor=flavor [default=$default_flavor]],
              	[],
                with_globus_flavor=${GLOBUS_FLAVOR:-${default_flavor}})

    AC_MSG_RESULT([found $GLOBUS_FLAVORS ($with_globus_flavor selected)])

    for flavor in $GLOBUS_FLAVORS ; do
      WANTED_OLDGAA_LIBS="$WANTED_OLDGAA_LIBS liboldgaa_$flavor.la"
      WANTED_SSL_UTILS_LIBS="$WANTED_SSL_UTILS_LIBS libssl_utils_"$flavor".la"
      WANTED_SOCK_LIBS="$WANTED_SOCK_LIBS libsock_$flavor.la"
      WANTED_CCAPI_LIBS="$WANTED_CCAPI_LIBS libvomsapi_"$flavor".la"
      WANTED_CAPI_LIBS="$WANTED_CAPI_LIBS libvomsc_"$flavor".la"
    done

    WANTED_API_LIBS="$WANTED_CCAPI_LIBS $WANTED_CAPI_LIBS"

    ac_globus_ldlib="-L$with_globus_prefix/lib"

    for flavor in $GLOBUS_FLAVORS ; do
      if test "x$flavor" = "x$with_globus_flavor" ; then
      	GLOBUS_CFLAGS="-I$with_globus_prefix/include/$flavor"
        GLOBUS_GSS_LIBS="$ac_globus_ldlib -lglobus_gssapi_gsi_$flavor -lglobus_gss_assist_$flavor -lcrypto_$flavor"
      fi
      if test "x$flavor" = "xgcc32" ; then
	      GLOBUS_GCC32_CFLAGS="-I$with_globus_prefix/include/$flavor"
        GLOBUS_GCC32_GSS_LIBS="$ac_globus_ldlib -lglobus_gssapi_gsi_$flavor -lglobus_gss_assist_$flavor -lcrypto_$flavor"
      fi
      if test "$flavor" = "gcc32dbg" ; then
        GLOBUS_GCC32DBG_CFLAGS="-I$with_globus_prefix/include/$flavor"
        GLOBUS_GCC32DBG_GSS_LIBS="$ac_globus_ldlib -lglobus_gssapi_gsi_$flavor -lglobus_gss_assist_$flavor -lcrypto_$flavor"
      fi
      if test "$flavor" = "gcc32dbgpthr" ; then
        GLOBUS_GCC32DBGPTHR_CFLAGS="-I$with_globus_prefix/include/$flavor"
        GLOBUS_GCC32DBGPTHR_GSS_LIBS="$ac_globus_ldlib -lglobus_gssapi_gsi_$flavor -lglobus_gss_assist_$flavor -lcrypto_$flavor"
      fi
      if test "$flavor" = "gcc32pthr" ; then
        GLOBUS_GCC32PTHR_CFLAGS="-I$with_globus_prefix/include/$flavor"
        GLOBUS_GCC32PTHR_GSS_LIBS="$ac_globus_ldlib -lglobus_gssapi_gsi_$flavor -lglobus_gss_assist_$flavor -lcrypto_$flavor"
      fi

      if test "x$flavor" = "xgcc64" ; then
	      GLOBUS_GCC64_CFLAGS="-I$with_globus_prefix/include/$flavor"
        GLOBUS_GCC64_GSS_LIBS="$ac_globus_ldlib -lglobus_gssapi_gsi_$flavor -lglobus_gss_assist_$flavor -lcrypto_$flavor"
      fi
      if test "$flavor" = "gcc64dbg" ; then
        GLOBUS_GCC64DBG_CFLAGS="-I$with_globus_prefix/include/$flavor"
        GLOBUS_GCC64DBG_GSS_LIBS="$ac_globus_ldlib -lglobus_gssapi_gsi_$flavor -lglobus_gss_assist_$flavor -lcrypto_$flavor"
      fi
      if test "$flavor" = "gcc64dbgpthr" ; then
        GLOBUS_GCC64DBGPTHR_CFLAGS="-I$with_globus_prefix/include/$flavor"
        GLOBUS_GCC64DBGPTHR_GSS_LIBS="$ac_globus_ldlib -lglobus_gssapi_gsi_$flavor -lglobus_gss_assist_$flavor -lcrypto_$flavor"
      fi
      if test "$flavor" = "gcc64pthr" ; then
        GLOBUS_GCC64PTHR_CFLAGS="-I$with_globus_prefix/include/$flavor"
        GLOBUS_GCC64PTHR_GSS_LIBS="$ac_globus_ldlib -lglobus_gssapi_gsi_$flavor -lglobus_gss_assist_$flavor -lcrypto_$flavor"
      fi
    done


    AC_LANG_PUSH(C)
    LDFLAGS_SAVE="$LDFLAGS"
    LDFLAGS="$LDFLAGS $GLOBUS_GSS_LIBS"
    AC_MSG_CHECKING([for globus_module_activate])
    AC_TRY_LINK([], [(void)globus_module_activate();],
                [ AC_DEFINE(HAVE_GLOBUS_MODULE_ACTIVATE, 1, [Define to 1 if you have globus_module_activate])
                  AC_MSG_RESULT(yes)],
                [AC_MSG_RESULT(no)])
    LDFLAGS="$LDFLAGS_SAVE"
    AC_LANG_POP(C)
    AC_SUBST(WANTED_OLDGAA_LIBS)
    AC_SUBST(WANTED_SSL_UTILS_LIBS)
    AC_SUBST(WANTED_SOCK_LIBS)
    AC_SUBST(WANTED_API_LIBS)

    AC_SUBST(GLOBUS_CFLAGS)
    AC_SUBST(GLOBUS_GCC32_CFLAGS)
    AC_SUBST(GLOBUS_GCC32DBG_CFLAGS)
    AC_SUBST(GLOBUS_GCC32DBGPTHR_CFLAGS)
    AC_SUBST(GLOBUS_GCC32PTHR_CFLAGS)

    AC_SUBST(GLOBUS_GCC64_CFLAGS)
    AC_SUBST(GLOBUS_GCC64DBG_CFLAGS)
    AC_SUBST(GLOBUS_GCC64DBGPTHR_CFLAGS)
    AC_SUBST(GLOBUS_GCC64PTHR_CFLAGS)

    AC_SUBST(GLOBUS_GSS_LIBS)
    AC_SUBST(GLOBUS_GCC32_GSS_LIBS)
    AC_SUBST(GLOBUS_GCC32DBG_GSS_LIBS)
    AC_SUBST(GLOBUS_GCC32DBGPTHR_GSS_LIBS)
    AC_SUBST(GLOBUS_GCC32PTHR_GSS_LIBS)

    AC_SUBST(GLOBUS_GCC64_GSS_LIBS)
    AC_SUBST(GLOBUS_GCC64DBG_GSS_LIBS)
    AC_SUBST(GLOBUS_GCC64DBGPTHR_GSS_LIBS)
    AC_SUBST(GLOBUS_GCC64PTHR_GSS_LIBS)
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
      CFLAGS="-g -O0 $CFLAGS"
      CXXFLAGS="-g -O0 $CXXFLAGS"
    fi

    AC_ARG_WITH(warnings,
      [  --with-warnings Compiles with maximum warnings],
      [ac_with_warnings="yes"],
      [ac_with_warnings="no"])

    if test "x$ac_with_warnings" = "xyes" ; then
      CFLAGS="-O -Wall -W $CFLAGS"
      CXXFLAGS="-O -Wall -w $CXXFLAGS"
    fi
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
	    [build_docs="yes"])

    AM_CONDITIONAL(BUILD_DOCS, test x$build_docs = xyes)
])

# AC_ENABLE_GLITE switch for glite
# -------------------------------------------------------
AC_DEFUN([AC_ENABLE_GLITE],
[
    AC_ARG_ENABLE(glite,
        [  --enable-glite     enable gLite  ],
        [ac_enable_glite="yes"],
        [ac_enable_glite="no"])

    AM_CONDITIONAL(ENABLE_GLITE, test x$ac_enable_glite = xyes)

    if test "x$ac_enable_glite" = "xno"; then
    	DISTTAR=$WORKDIR
    	AC_SUBST(DISTTAR)
#	EDG_SET_RPM_TOPDIR
    	AC_SUBST(LOCATION_ENV, "VOMS_LOCATION")
    	AC_SUBST(LOCATION_DIR, "$prefix")
    	AC_SUBST(VAR_LOCATION_ENV, "VOMS_LOCATION_VAR")
    	AC_DEFINE(LOCATION_ENV, "VOMS_LOCATION", [Environment variable name])
    	AC_DEFINE(LOCATION_DIR, "$prefix", [Location of system directory])
    	AC_DEFINE(USER_DIR, ".edg", [Location of user directory])
    else
    	AC_MSG_RESULT([Preparing for gLite environment])
    	AC_GLITE
    	AC_SUBST(LOCATION_ENV, "GLITE_LOCATION")
    	AC_SUBST(LOCATION_DIR, "/opt/glite")
    	AC_SUBST(VAR_LOCATION_ENV, "GLITE_LOCATION_VAR")
    	AC_DEFINE(LOCATION_ENV, "GLITE_LOCATION", [Environment variable name])
    	AC_DEFINE(LOCATION_DIR, "/opt/glite", [Location of system directory])
    	AC_DEFINE(USER_DIR, ".glite", [Location of user directory])
    fi
])

# EDG_SET_RPM_TOPDIR(DIRECTORY)
# -----------------------------
AC_DEFUN([EDG_SET_RPM_TOPDIR],
[
    AC_MSG_CHECKING([for rpm topdir])
    
    AC_ARG_WITH([rpm-dir],
            [  --with-rpm-dir=DIR      rpm topdir in DIR [`pwd`]],
            [ac_with_rpm_topdir=$withval],
            [ac_with_rpm_topdir=`pwd`])

    if test -d $ac_with_rpm_topdir ; then
      AC_MSG_RESULT([$ac_with_rpm_topdir found])
    else
      AC_MSG_RESULT([$ac_with_rpm_topdir not found])
    fi

    RPM_TOPDIR=$ac_with_rpm_topdir
    AC_SUBST(RPM_TOPDIR)
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
                [AC_DEFINE(HAVE_STRNDUP, 1, [Define to 1 if you have time_t _timezone type in time.h])
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
        (void)getsockname(0, NULL, &addrlen); 
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

# AC_OPENSSL_EXT_METHOD check whether X509V3_EXT_METHOD has a 
# member called it (only in recent openssl version)
# ------------------------------------------------------------
AC_DEFUN([AC_OPENSSL_EXT_METHOD],
[
    AC_MSG_CHECKING([for it member in X509V3_EXT_METHOD])

    CFLAGS_SAVE="$CFLAGS"
    CFLAGS="$CFLAGS $GLOBUS_CFLAGS"

    AC_TRY_COMPILE(
      [
        #include <openssl/x509v3.h>
      ],
      [
        X509V3_EXT_METHOD it;
        it.it = NULL;
      ],
      [ac_have_x509v3_member_it="yes"],
      [ac_have_x509v3_member_it="no"]
    )

    if test "x$ac_have_socklen_t" = "xyes" ; then
      AC_DEFINE(HAVE_X509V3_EXT_METHOD_IT, 1, [Define to 1 if X509V3_EXT has a member it]) 
    fi

    AC_MSG_RESULT([$ac_have_x509v3_member_it])

    CFLAGS="$CFLAGS_SAVE"
])

# AC_VOMS_OPENSSL_EVP_MD_CTX
# ------------------------------------------------------------
AC_DEFUN([AC_VOMS_OPENSSL_EVP_MD_CTX],
[
    AC_MSG_CHECKING([for EVP_MD_CTX_init])
    CPPFLAGS_SAVE="$CPPFLAGS"
    CPPFLAGS="$CPPFLAGS $GLOBUS_CFLAGS $GLOBUS_GSS_LIBS"
    AC_LANG_PUSH(C++)
    AC_TRY_LINK(
      [
        #include <$with_globus_location/include/$with_globus_flavor/openssl/evp.h>
      ],
      [
        EVP_MD_CTX mp; 
        (void)EVP_MD_CTX_init(&mp)
      ],
      [AC_DEFINE(HAVE_EVP_MD_CTX_INIT, 1, [Define to 1 if you have EVP_MD_CTX_init])
       AC_MSG_RESULT(yes)],
      [AC_MSG_RESULT(no)]
    )
    CPPFLAGS="$CPPFLAGS_SAVE"

    AC_MSG_CHECKING([for EVP_MD_CTX_cleanup])
    CPPFLAGS_SAVE="$CPPFLAGS"
    CPPFLAGS="$CPPFLAGS $GLOBUS_CFLAGS $GLOBUS_GSS_LIBS"
    AC_TRY_LINK(
      [
        #include <$with_globus_location/include/$with_globus_flavor/openssl/evp.h>
      ],
      [
        EVP_MD_CTX mp; 
        (void)EVP_MD_CTX_cleanup(&mp)
      ],
      [AC_DEFINE(HAVE_EVP_MD_CTX_CLEANUP, 1, [Define to 1 if you have EVP_MD_CTX_cleanup])
       AC_MSG_RESULT(yes)],
      [AC_MSG_RESULT(no)]
      )
    AC_LANG_POP(C++)
    CPPFLAGS="$CPPFLAGS_SAVE"
])

# AC_VOMS_LONG_LONG check whether long long type is present
# ------------------------------------------------------------
AC_DEFUN([AC_VOMS_LONG_LONG],
[
    AC_MSG_CHECKING([for long long])

    AC_TRY_COMPILE(
      [],
      [
        long long i;
      ],
      [ac_have_long_long_t="yes"],
      [ac_have_long_long_t="no"]
    )

    if test "x$ac_have_long_long_t" = "xyes" ; then
      AC_DEFINE(HAVE_LONG_LONG_T, 1, [Define to 1 if you have long long]) 
    fi

    AC_MSG_RESULT([$ac_have_long_long_t])
])

# AC_VOMS_GLOBUS_OFF_T check whether GLOBUS_OFF type is present
# -------------------------------------------------------------------
AC_DEFUN([AC_VOMS_GLOBUS_OFF_T],
[
    AC_MSG_CHECKING([for GLOBUS_OFF_T])

    CFLAGS_SAVE="$CFLAGS"
    CFLAGS="$CFLAGS $GLOBUS_CFLAGS"

    AC_TRY_COMPILE(
      [
        #include <globus_common.h>
      ], 
      [GLOBUS_OFF_T goff],
      [ac_have_globus_off_t="yes"], 
      [ac_have_globus_off_t="no"]
    )

    if test "x$ac_have_globus_off_t" = "xyes" ; then
      AC_DEFINE(HAVE_GLOBUS_OFF_T, 1, [Define to 1 if you have GLOBUS_OFF_T]) 
    fi

    AC_MSG_RESULT([$ac_have_globus_off_t])

    CFLAGS="$CFLAGS_SAVE"
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

# AC_VOMS_STRUCT_IOVEC check whether you have the iovec struct
# in uio.h
# -------------------------------------------------------------------
AC_DEFUN([AC_VOMS_STRUCT_IOVEC],
[
    AC_MSG_CHECKING([for struct iovec])

    AC_TRY_COMPILE(
      [
        #include <sys/uio.h>
      ], 
      [
        struct iovec v;
      ],
      [ac_have_struct_iovec="yes"], 
      [ac_have_struct_iovec="no"]
    )

    if test "x$ac_have_globus_off_t" = "xyes" ; then
      AC_DEFINE(HAVE_STRUCT_IOVEC, 1, [Define to 1 if you have iovec struct in uio.h]) 
    fi

    AC_MSG_RESULT([$ac_have_struct_iovec])
])

# AC_VOMS_GLOBUS_CONFIG_H check whether globus_config.h is present 
# -------------------------------------------------------------------
AC_DEFUN([AC_VOMS_GLOBUS_CONFIG_H],
[
    AC_MSG_CHECKING([for globus_config.h])

    CFLAGS_SAVE="$CFLAGS"
    CFLAGS="$CFLAGS $GLOBUS_CFLAGS"

    AC_TRY_COMPILE(
      [
        #include <globus_config.h>
      ], 
      [],
      [ac_have_globus_config_h="yes"], 
      [ac_have_globus_config_h="no"]
    )

    if test "x$ac_have_globus_config_h" = "xno" ; then
      proc=`./config.guess | cut -d- -f1`
      arch=`./config.guess | cut -d- -f3`
      case "$proc" in
        i*86) proc=X86 ;;
        ia64) proc=IA64 ;;
        *) proc="" ;;
      esac
      arch=`echo $arch | tr a-z A-Z`
      echo "#define BUILD_LITE 1" > include/globus_config.h
      echo "#define BUILD_DEBUG 1" >> include/globus_config.h
      echo "#define TARGET_ARCH_$arch 1" >> include/globus_config.h
      if ! test "x$proc" = "x"; then
        echo "#define TARGET_ARCH_$proc 1" >> include/globus_config.h
      fi
    fi

    AC_MSG_RESULT([$ac_have_globus_config_h])

    CFLAGS="$CFLAGS_SAVE"
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
        AC_DEFINE(__THROW_BAD_ALLOC, return NULL, __THROW_BAD_ALLOC)
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

AC_DEFUN([TEST_USE_BSD],
[
    AC_MSG_CHECKING([wether _BSD_SOURCE must be defined])

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
