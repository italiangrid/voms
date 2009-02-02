AC_DEFUN([AC_VOMS_LIBRARY],
[
    globus_flavor=$1
    candidatepath=$2

    if test "x$candidatepath" = "x" ; then
      libpath=$GLOBUS_LOCATION/lib
    else
      libpath=$candidatepath/lib
    fi

    if test "x$globus_flavor" = "x" ; then
      globus_flavor="none"
    fi

    AC_MSG_CHECKING([for library to use with globus library: $globus_flavor])

    if test "x$globus_flavor" = "xnone" ; then
      AC_MSG_RESULT([libvomsapi])
      VOMS_LIBRARY="-lvomsapi"
    elif test -e $libpath/libglobus_gssapi_gsi_$globus_flavor.so ; then 
      if ( (ldd $libpath/libglobus_gssapi_gsi_$globus_flavor.so|grep crypto|cut -d'=' -f2|grep $globus_flavor) >/dev/null 2>&1 ); then
        AC_MSG_RESULT([libvomsapi_$globus_flavor])
        VOMS_LIBRARY="-lvomsapi_$globus_flavor"
      else
        AC_MSG_RESULT([libvomsapi])
        VOMS_LIBRARY="-lvomsapi"
      fi
    else
      AC_MSG_ERROR([flavor $globus_flavor is unknown])
    fi

    AC_SUBST(VOMS_LIBRARY)
])
