#!/usr/bin/env bash
#
# Copyright (c) Istituto Nazionale di Fisica Nucleare
# Licensed under the EUPL
#
# Syntax: ./add-deps-redhat.sh [install doc tools]

set -e

. /etc/os-release

INSTALL_DOC_TOOLS=${1:-"false"}

package_list="\
  file \
  gdb \
  expat-devel \
  autoconf \
  automake \
  make \
  libtool \
  openssl-devel \
  gsoap-devel \
  bison \
  gcc-c++"

if ! type git > /dev/null 2>&1; then
  if [ "${ID}" = "centos" ] && [ "${VERSION_ID}" = "7" ]; then
    package_list="${package_list} git236"
  else
    package_list="${package_list} git"
  fi
fi


if [ ${INSTALL_DOC_TOOLS} = "true" ]; then
  package_list="${package_list} \
    libxslt \
    docbook-style-xsl \
    doxygen"
fi

yum install -y ${package_list}
