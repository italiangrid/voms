<!--
SPDX-FileCopyrightText: 2025 Istituto Nazionale di Fisica Nucleare

SPDX-License-Identifier: Apache-2.0
-->

# Changelog

## 2.1.4 (2026-07-31)

### What's changed

* Support for OpenSSL 4
* Remove dead code for Windows, smart card support, DejaGnu testsuite, Globus, Class Add's and more
* Build in C++17 mode
* Add more platforms to CI builds
* Some cleanup in build infrastructure

## 2.1.3 (2025-12-18)

### What's changed

* voms-proxy-init now reports errors similarly to the Java clients, in particular for expired certificates, suspended users, expired AUPs
* voms-proxy-init doesn't contact any more the VOMS server legacy endpoint
* add CI workflow to build RPMs and publish the release
* add a CHANGELOG.md file, used by the above workflow
