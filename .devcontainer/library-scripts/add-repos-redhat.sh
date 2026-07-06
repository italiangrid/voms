#!/usr/bin/env bash
#
# Copyright (c) Istituto Nazionale di Fisica Nucleare
# Licensed under the EUPL
#
# Syntax: ./add-repos-redhat.sh

set -e

. /etc/os-release

repo_list="epel-release"

yum install -y ${repo_list}
