<!--
SPDX-FileCopyrightText: 2025 Istituto Nazionale di Fisica Nucleare

SPDX-License-Identifier: Apache-2.0
-->

# Changelog

## 2.1.4 (2026-10-07)

### What's changed

* Add support for OpenSSL 4
* Remove support for OpenSSL versions older than 1.1
* Fallback to SHA-256 for signatures instead of SHA-1
* Improve the check that certificate and private key match
* Remove dead code for Windows, smart card support, DejaGnu testsuite, Globus, Class Add's and more
* Build in C++17 mode
* Improve const-correctness and fix related warnings
* Add more platforms to CI builds
* Some cleanup in build infrastructure

## 2.1.3 (2025-12-18)

### What's changed

* voms-proxy-init now reports errors similarly to the Java clients, in particular for expired certificates, suspended users, expired AUPs
* voms-proxy-init doesn't contact any more the VOMS server legacy endpoint
* add CI workflow to build RPMs and publish the release
* add a CHANGELOG.md file, used by the above workflow
