#!/usr/bin/env bash
#
# Copyright (c) Istituto Nazionale di Fisica Nucleare
# Licensed under the EUPL
#
# Syntax: ./add-repos-redhat.sh

set -e

. /etc/os-release

repo_list="epel-release"

if [ "${ID}" = "centos" ] && [ "${VERSION_ID}" = "7" ]; then
  repo_list="${repo_list} https://repo.ius.io/ius-release-el7.rpm"
fi

yum install -y ${repo_list}
