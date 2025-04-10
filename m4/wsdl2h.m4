dnl Copyright (c) Istituto Nazionale di Fisica Nucleare (INFN). 2006-2013.
dnl
dnl Licensed under the Apache License, Version 2.0 (the "License");
dnl you may not use this file except in compliance with the License.
dnl You may obtain a copy of the License at
dnl
dnl     http://www.apache.org/licenses/LICENSE-2.0
dnl
dnl Unless required by applicable law or agreed to in writing, software
dnl distributed under the License is distributed on an "AS IS" BASIS,
dnl WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
dnl See the License for the specific language governing permissions and
dnl limitations under the License.

AC_DEFUN([AC_WSDL2H],
[
	
	AC_ARG_WITH(gsoap-wsdl2h,
        	[  --with-gsoap-wsdl2h=CMD     the wsdl2h command that should be used. (/usr)],
        	[with_gsoap_wsdl2h="$withval"],
        	[with_gsoap_wsdl2h="/usr/bin/wsdl2h"])
	
	dnl wsdl2h macros. we try to udnerstand which flags need to be used depending
	dnl on wsdl2h version
	AC_MSG_CHECKING([wsdl2h version])

	WSDL2H="$with_gsoap_wsdl2h"
	
	if ! test -e "$WSDL2H"; then
		AC_MSG_ERROR("wsdl2h executable: $WSDL2H does not exist.")
	fi

	if ! test -x "$WSDL2H"; then
		AC_MSG_ERROR("wsdl2h executable: $WSDL2H cannot be executed.")
	fi
	
	dnl The ridicoulous escaping with quadrigraph is needed as square brakets
	dnl confuse m4. 
	dnl 
	dnl @<:@  becomes [
	dnl @:>@  becomes ]
	dnl
	dnl Newer versions support -V parameter.
	wsdl2h_version=$($WSDL2H -V 2>/dev/null)
	if test -z "$wsdl2h_version"; then
		wsdl2h_version=$($WSDL2H -help 2>&1 | grep release | grep -o '@<:@0-9@:>@\.@<:@0-9@:>@\.@<:@0-9@:>@*$')
	fi

	normalized_version=$(printf "%02d%02d%02d" $(echo $wsdl2h_version | tr '.' ' '))

	WSDL2H_FLAGS=""

	if test "$normalized_version" -ge "010216"; then
		WSDL2H_FLAGS="-z1"
	elif test "$normalized_version" -ge "010200"; then
		WSDL2H_FLAGS="-z"
	else
		AC_MSG_ERROR([unsupported wsdl2h version: $wsdl2h_version])
	fi

	AC_MSG_RESULT([yes. wsdl2h version $wsdl2h_version detected.])
	AC_SUBST(WSDL2H)
	AC_SUBST(WSDL2H_FLAGS)

	WSDL2H_DIR=$(AS_DIRNAME([$WSDL2H]))
	SOAPCPP2=$WSDL2H_DIR/soapcpp2

	if ! test -e "$SOAPCPP2"; then
		AC_MSG_ERROR("soapcpp2 executable: $SOAPCPP2 does not exist.")
	fi

	if ! test -x "$SOAPCPP2"; then
		AC_MSG_ERROR("soapcpp2 executable: $SOAPCPP2 cannot be executed.")
	fi
	
    AC_SUBST([SOAPCPP2])
])
