# AC_OPENSSL checks system openssl availability
# ---------------------------------------------
AC_DEFUN([AC_OPENSSL],
[
  AC_ARG_WITH(openssl_prefix,
              [ --with-openssl-prefix=PFX    prefix where OpenSSL (non-globus) is installed. (/usr)],
              [with_openssl_prefix="$withval"],
              [with_openssl_prefix=/usr])

  AC_ARG_WITH(openssl_libs,
              [ --with-openssl-libs do you want OpenSSL only libs? (yes)],
              [ with_openssl_libs="$withval"],
              [ with_openssl_libs="yes"])

  if test "x$with_openssl_libs" != "xno"  -a "x$with_openssl_libs" != "xyes" ; then
     AC_MSG_ERROR([Value of --with-openssl-libs must be either "yes" or "no"])
  fi  

  SAVE_LD_LIBRARY_PATH=$LD_LIBRARY_PATH
  LD_LIBRARY_PATH="$with_openssl_prefix/lib"

  AC_LANG_PUSH(C)
  AC_CHECK_LIB(crypto, CRYPTO_num_locks, [found=yes], [found=no])
  AC_LANG_POP(C) 

  if test "x$found" = "xyes"; then
    NO_GLOBUS_FLAGS="-I$with_openssl_prefix/include"
    OPENSSL_LIBS="-L$with_openssl_prefix/lib -lcrypto -lssl"
    AC_SUBST(NO_GLOBUS_FLAGS)
    AC_SUBST(OPENSSL_LIBS)
    AC_MSG_CHECKING([for system OpenSSL version])
    if test "x$with_openssl_libs" = "xyes" ; then
      WANTED_API_LIBS="$WANTED_API_LIBS libvomsapi-nog.la"
      WANTED_ATTCERT_LIBS="$WANTED_ATTCERT_LIBS libattributes_nog.la"
      WANTED_SSL_UTILS_LIBS="$WANTED_SSL_UTILS_LIBS libssl_utils-nog.la"
      WANTED_OLDGAA_LIBS="$WANTED_OLDGAA_LIBS liboldgaa-nog.la"
      WANTED_UTIL_LIBS="$WANTED_UTIL_LIBS libutilities_nog.la libutilc_nog.la"
    fi
    cat >conftest.h <<HERE
#include <openssl/opensslv.h>
OPENSSL_VERSION_TEXT
HERE
    openssl_version=`$CPP -I$NO_GLOBUS_FLAGS -o - -P conftest.h`
    AC_MSG_RESULT($openssl_version)
    rm -f conftest.h
  fi
  LD_LIBRARY_PATH="$SAVE_LD_LIBRARY_PATH"
])

# AC_GLOBUS checks globus prefix, looks for globus 
# flavors, selects globus flavor and define wanted lib
# according to flavor installed with their own compiler
# flags 
# -------------------------------------------------------
AC_DEFUN([AC_GLOBUS],
[
    AC_ARG_WITH(globus_prefix,
	[  --with-globus-prefix=PFX     prefix where GLOBUS is installed. (/opt/globus)],
	[with_globus_prefix="$withval"],
        [with_globus_prefix=${GLOBUS_LOCATION:-/opt/globus}])

    AC_MSG_CHECKING([for GLOBUS installation at $with_globus_prefix])
    # to be added
    AC_MSG_RESULT([yes])

    AC_ARG_WITH(bit64,
                [  --with-bit64    use 64bit libraries only.],
                [with_64bit="yes"],
                [with_64bit="no"])
                
    LD_LIBRARY_PATH="$LD_LIBRARY_PATH:$with_globus_prefix/lib"
    AC_MSG_CHECKING([for GLOBUS flavors])

    for i in `ls $with_globus_prefix/include`; do
      if test "x$i" != "xldap_backend"; then
        GLOBUS_FLAVORS="$GLOBUS_FLAVORS $i"
      fi
    done

    if test "x$with_64bit" == "xno" ; then
      if test -e $with_globus_prefix/include/gcc32dbg ; then
        default_flavor=gcc32dbg
      elif test -e $with_globus_prefix/include/gcc64dbg ; then
        default_flavor=gcc64dbg
      else
        default_flavor=""
      fi
    else
      if test -e $with_globus_prefix/include/gcc64dbg ; then
        default_flavor=gcc64dbg
      else
        default_flavor=""
      fi
    fi      

    AC_ARG_WITH(globus_flavor,
              	[  --with-globus-flavor=flavor  default=${GLOBUS_FLAVOR:-none}],
              	[with_globus_flavor="$withval"],
                [with_globus_flavor=${GLOBUS_FLAVOR}])

    AC_MSG_RESULT([found $GLOBUS_FLAVORS ($with_globus_flavor selected)])

    if test "x$with_globus_flavor" = "x" ; then
      if test "x$USE_OLDGAA_LIB" = "x"; then
        USE_OLDGAA_LIB="liboldgaa.la"
      fi
      if test "x$USE_SSL_UTILS_LIB" = "x"; then
        USE_SSL_UTILS_LIB="libssl_utils.la"
      fi
      if test "x$USE_SOCK_LIB" = "x"; then
        USE_SOCK_LIB="libsock.la"
      fi
      if test "x$USE_CCAPI_LIB" = "x"; then
        USE_CCAPI_LIB="libvomsapi.la"
      fi
      if test "x$USE_CAPI_LIB" = "x"; then
        USE_CAPI_LIB="libvomsc.la"
      fi
      if test "x$USE_ATTCERT_LIB" = "x"; then
        USE_ATTCERT_LIB="libattcert.la"
      fi
      if test "x$USE_CCATTCERT_LIB" = "x"; then
        USE_CCATTCERT_LIB="libccattcert.la"
      fi

      WANTED_OLDGAA_LIBS="$WANTED_OLDGAA_LIBS liboldgaa.la"
      WANTED_SSL_UTILS_LIBS="$WANTED_SSL_UTILS_LIBS libssl_utils.la"
      WANTED_SOCK_LIBS="$WANTED_SOCK_LIBS libsock.la"
      WANTED_ATTCERT_LIBS="$WANTED_ATTCERT_LIBS libattcert.la libccattcert.la"
      WANTED_API_LIBS="$WANTED_API_LIBS libvomsapi.la libvomsc.la"
      WANTED_UTIL_LIBS="$WANTED_UTIL_LIBS libutilities.la libutilc.la"
    fi    
    new_flavors=""

    for flavor in $GLOBUS_FLAVORS ; do
      if test "x$with_globus_flavor" != "x" ; then
        if test "x$flavor" == "x$with_globus_flavor" ; then
          new_flavors="$flavor $new_flavors"
        fi
      else
          new_flavors="$GLOBUS_FLAVORS"
      fi
    done

    GLOBUS_FLAVORS=""

    for flavor in $new_flavors ; do
      if test "x$with_64bit" == "xyes" ; then
        echo $flavor | grep 64 >/dev/null
        if test $? -eq 0 ; then
          GLOBUS_FLAVORS="$GLOBUS_FLAVORS $flavor"
        fi
      else
        GLOBUS_FLAVORS="$flavor $GLOBUS_FLAVORS"
      fi
    done

    AC_MSG_RESULT([Final globus flavors: ${GLOBUS_FLAVORS}])

    for flavor in $GLOBUS_FLAVORS ; do
      if test "x$USE_OLDGAA_LIB" = "x"; then
        USE_OLDGAA_LIB="liboldgaa_$flavor.la"
      fi
      if test "x$USE_SSL_UTILS_LIB" = "x"; then
        USE_SSL_UTILS_LIB="libssl_utils_$flavor.la"
      fi
      if test "x$USE_SOCK_LIB" = "x"; then
        USE_SOCK_LIB="libsock_$flavor.la"
      fi
      if test "x$USE_CCAPI_LIB" = "x"; then
        USE_CCAPI_LIB="libvomsapi_$flavor.la"
      fi
      if test "x$USE_CAPI_LIB" = "x"; then
        USE_CAPI_LIB="libvomsc_$flavor.la"
      fi
      if test "x$USE_ATTCERT_LIB" = "x"; then
        USE_ATTCERT_LIB="libattcert_$flavor.la"
      fi
      if test "x$USE_CCATTCERT_LIB" = "x"; then
        USE_CCATTCERT_LIB="libccattcert_$flavor.la"
      fi
      WANTED_OLDGAA_LIBS="$WANTED_OLDGAA_LIBS liboldgaa_$flavor.la"
      WANTED_SSL_UTILS_LIBS="$WANTED_SSL_UTILS_LIBS libssl_utils_"$flavor".la"
      WANTED_SOCK_LIBS="$WANTED_SOCK_LIBS libsock_$flavor.la"
      WANTED_CCAPI_LIBS="$WANTED_CCAPI_LIBS libvomsapi_"$flavor".la"
      WANTED_CAPI_LIBS="$WANTED_CAPI_LIBS libvomsc_"$flavor".la"
      WANTED_ATTCERT_LIBS="$WANTED_ATTCERT_LIBS libattcert_"$flavor".la libccattcert_"$flavor".la"
      WANTED_UTIL_LIBS="$WANTED_UTIL_LIBS libutilities.la libutilc.la"
    done

    WANTED_API_LIBS="$WANTED_API_LIBS $WANTED_CCAPI_LIBS $WANTED_CAPI_LIBS"

    ac_globus_ldlib="-L$with_globus_prefix/lib"

    if test "x$with_globus_flavor" = "x" ; then
      with_globus_flavor=${default_flavor}
    fi

    for flavor in $GLOBUS_FLAVORS ; do
      if test "x$flavor" = "x$with_globus_flavor" ; then
      	GLOBUS_CFLAGS="-I$with_globus_prefix/include/$flavor"
        GLOBUS_GSS_LIBS="$ac_globus_ldlib -lglobus_gssapi_gsi_$flavor -lglobus_gss_assist_$flavor -lcrypto_$flavor"
      fi
      if test "x$flavor" = "xgcc32" ; then
	      GLOBUS_GCC32_CFLAGS="-I$with_globus_prefix/include/$flavor"
        GLOBUS_GCC32_GSS_LIBS="$ac_globus_ldlib -lglobus_gssapi_gsi_$flavor -lglobus_gss_assist_$flavor -lcrypto_$flavor"
      fi
      if test "x$flavor" = "xgcc32dbg" ; then
        GLOBUS_GCC32DBG_CFLAGS="-I$with_globus_prefix/include/$flavor"
        GLOBUS_GCC32DBG_GSS_LIBS="$ac_globus_ldlib -lglobus_gssapi_gsi_$flavor -lglobus_gss_assist_$flavor -lcrypto_$flavor"
      fi
      if test "x$flavor" = "xgcc32dbgpthr" ; then
        GLOBUS_GCC32DBGPTHR_CFLAGS="-I$with_globus_prefix/include/$flavor"
        GLOBUS_GCC32DBGPTHR_GSS_LIBS="$ac_globus_ldlib -lglobus_gssapi_gsi_$flavor -lglobus_gss_assist_$flavor -lcrypto_$flavor"
      fi
      if test "x$flavor" = "xgcc32pthr" ; then
        GLOBUS_GCC32PTHR_CFLAGS="-I$with_globus_prefix/include/$flavor"
        GLOBUS_GCC32PTHR_GSS_LIBS="$ac_globus_ldlib -lglobus_gssapi_gsi_$flavor -lglobus_gss_assist_$flavor -lcrypto_$flavor"
      fi

      if test "x$flavor" = "xgcc64" ; then
	      GLOBUS_GCC64_CFLAGS="-I$with_globus_prefix/include/$flavor"
        GLOBUS_GCC64_GSS_LIBS="$ac_globus_ldlib -lglobus_gssapi_gsi_$flavor -lglobus_gss_assist_$flavor -lcrypto_$flavor"
      fi
      if test "x$flavor" = "xgcc64dbg" ; then
        GLOBUS_GCC64DBG_CFLAGS="-I$with_globus_prefix/include/$flavor"
        GLOBUS_GCC64DBG_GSS_LIBS="$ac_globus_ldlib -lglobus_gssapi_gsi_$flavor -lglobus_gss_assist_$flavor -lcrypto_$flavor"
      fi
      if test "x$flavor" = "xgcc64dbgpthr" ; then
        GLOBUS_GCC64DBGPTHR_CFLAGS="-I$with_globus_prefix/include/$flavor"
        GLOBUS_GCC64DBGPTHR_GSS_LIBS="$ac_globus_ldlib -lglobus_gssapi_gsi_$flavor -lglobus_gss_assist_$flavor -lcrypto_$flavor"
      fi
      if test "x$flavor" = "xgcc64pthr" ; then
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
    AC_SUBST(WANTED_ATTCERT_LIBS)
    AC_SUBST(WANTED_UTIL_LIBS)

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

    AC_SUBST(USE_OLDGAA_LIB)
    AC_SUBST(USE_SSL_UTILS_LIB)
    AC_SUBST(USE_SOCK_LIB)
    AC_SUBST(USE_CCAPI_LIB)
    AC_SUBST(USE_CAPI_LIB)
    AC_SUBST(USE_ATTCERT_LIB)
    AC_SUBST(USE_CCATTCERT_LIB)

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
      CFLAGS="-O -Wall -W $CFLAGS"
      CXXFLAGS="-O -Wall -w $CXXFLAGS"
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

AC_DEFUN([AC_JAVA],
[
  AC_ARG_ENABLE(java, 
    [  --enable-java   Enable compilation of the Java libraries],
    [
      case "$enableval" in
      yes) have_java="yes" ;;
      no)  have_java="no" ;;
      *) AC_MSG_ERROR([bad value $(enableval) for --enable-java]) ;;
      esac
    ],
    [ have_java="yes" ])

  AM_CONDITIONAL(BUILD_JAVA, test x$have_java = xyes)

  if test "x$have_java" = "xyes"; then
    AC_MSG_CHECKING([for JAVA])
    AC_ARG_WITH(java-home,
      [  --with-java-home=DIR    Specifies where to find the java installation, default=$JAVA_HOME],
      [ javahome="$withval"],
      [ javahome="$JAVA_HOME"])
# Find include dirs
    javainc="`find $javahome/include -type d -exec echo -n '-I{} ' ';'`"
    JAVA_INCLUDES="$javainc"
    JHOME="$javahome"
    AC_MSG_RESULT($javahome)
    AC_SUBST(JAVA_INCLUDES)
    AC_SUBST(JHOME)
  fi

  if test "x$have_java" = "xyes"; then
    AC_MSG_CHECKING([for bouncycastle])
  fi

  AC_ARG_WITH(bc,
    [  --with-bc=FILE          Specifies the location of the bouncycastle jar, default=$CLASSPATH],
    [ wbc="$withval"],
    [ wbc=""])

  if test "x$wbc" = "x"; then
    if test "x$have_java" = "xyes"; then
      AC_MSG_RESULT([hope it is in $CLASSPATH])
    fi
  else
    AC_MSG_RESULT([specified: $wbc])
  fi

  if test "x$have_java" = "xyes"; then
    AC_MSG_CHECKING([for log4j])
  fi

  AC_ARG_WITH(log4j,
    [  --with-log4j=FILE        Specifies the location of the log4j jar, default=$CLASSPATH],
    [ wlog4j="$withval"],
    [ wlog4j=""])
  if test "x$wlog4j" = "x"; then
    if test "x$have_java" = "xyes"; then
      AC_MSG_RESULT([hope it is in $CLASSPATH])
    fi
  else
    AC_MSG_RESULT([specified: $wlog4j])
  fi

  if test "x$have_java" = "xyes"; then
    AC_MSG_CHECKING([for cog])
  fi

  AC_ARG_WITH(cog,
    [  --with-cog=jars         Colon-separated list of cog jars, default = $CLASSPATH],
    [  wcog="$withval"],
    [  wcog=""])
  if test "x$wcog" = "x"; then
    if test "x$have_java" = "xyes"; then
      AC_MSG_RESULT([hope it is in $CLASSPATH])
    fi
  else
    AC_MSG_RESULT([specified: $wcog])
  fi

  if test "x$have_java" = "xyes"; then
    AC_MSG_CHECKING([for commons-cli])
  fi

  AC_ARG_WITH(commons-cli,
    [  --with-commons-cli=jars  Specifies the location of the commons-cli jar, default = $CLASSPATH],
    [  wcomcli="$withval"],
    [  wcomcli=""])
  if test "x$wcomcli" = "x"; then
    if test "x$have_java" = "xyes"; then
      AC_MSG_RESULT([hope it is in $CLASSPATH])
    fi
  else
    AC_MSG_RESULT([specified: $wcomcli])
  fi

  if test "x$have_java" = "xyes"; then
    AC_MSG_CHECKING([for commons-lang])
  fi

  AC_ARG_WITH(commons-lang,
    [  --with-commons-lang=jars  Specifies the location of the commons-lang jar, default = $CLASSPATH],
    [  wcomlang="$withval"],
    [  wcomlang=""])
  if test "x$wcomlang" = "x"; then
    if test "x$have_java" = "xyes"; then
      AC_MSG_RESULT([hope it is in $CLASSPATH])
    fi
  else
    AC_MSG_RESULT([specified: $wcomlang])
  fi

  AC_ARG_WITH(java-only,
    [ --with-java-only     Builds only the java APIs ],
    [ wjavaall="$withval" ],
    [ wjavaall="no"])

  AM_CONDITIONAL(BUILD_JAVA_ONLY, test x$wjavaall = xyes)
          
  JAVA_CLASSPATH=".:$wbc:$wlog4j:$wcog:$wcomcli:$wcomlang"
  JAVA_CLASSPATH2=""

#  JAVA_CLASSPATH2='.:/data/marotta/cog-1.1/lib/cog-jglobus.jar:${top_srcdir}/jars/commons-cli-1.0.jar:${top_srcdir}/jars/commons-lang-2.2.jar:/data/marotta/cog-1.1/lib/cryptix32.jar:/data/marotta/cog-1.1/lib/cryptix-asn1.jar:/data/marotta/cog-1.1/lib/cryptix.jar:/data/marotta/cog-1.1/lib/jgss.jar:/data/marotta/cog-1.1/lib/puretls.jar'

  AC_MSG_CHECKING([CLASSPATH is $JAVA_CLASSPATH2])
  AC_SUBST(JAVA_CLASSPATH)    
  AC_SUBST(JAVA_CLASSPATH2)    
  
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
    	AC_SUBST(LOCATION_DIR, "${prefix}")
    	AC_SUBST(VAR_LOCATION_ENV, "VOMS_LOCATION_VAR")
    	AC_DEFINE(LOCATION_ENV, "VOMS_LOCATION", [Environment variable name])
    	AC_DEFINE_UNQUOTED(LOCATION_DIR, "$prefix", [Location of system directory])
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

    if test "x$ac_have_struct_iovec" = "xyes" ; then
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
      proc=`$ac_aux_dir/config.guess | cut -d- -f1`
      arch=`$ac_aux_dir/config.guess | cut -d- -f3`
      case "$proc" in
        i*86) proc=X86 ;;
        ia64) proc=IA64 ;;
        *) proc="" ;;
      esac
      arch=`echo $arch | tr a-z A-Z`
      echo "#define BUILD_LITE 1" > src/include/globus_config.h
      echo "#define BUILD_DEBUG 1" >> src/include/globus_config.h
      echo "#define TARGET_ARCH_$arch 1" >> src/include/globus_config.h
      if ! test "x$proc" = "x"; then
        echo "#define TARGET_ARCH_$proc 1" >> src/include/globus_config.h
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

# AC_VOMS_GLOBUS_CONFIG_H check whether globus_config.h is present 
# -------------------------------------------------------------------
AC_DEFUN([AC_UTEST],
[
  AC_ARG_ENABLE(unit-test,
    [  --enable-unit-test   Enable unit test],
    [
      case "$enableval" in
      yes) have_unit_test="yes" ;;
      no)  have_unit_test="no" ;;
      *) AC_MSG_ERROR([bad value $(enableval) for --enable-unit-test]) ;;
      esac
    ],
    [ have_unit_test="no" ])

  AM_CONDITIONAL(WANT_UNIT_TEST, test x$have_unit_test = xyes)
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
