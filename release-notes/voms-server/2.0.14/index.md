---
layout: default
title: VOMS Server v. 2.0.14
rfcs:
  - id: VOMS-749
    title: VOMS server reports OpenSSL errors in a very obscure way
  - id: VOMS-744
    title: Improve VOMS certificate type detection and proxy name validation
features:
  - id: VOMS-751
    title: Provide a simple tool to test VOMS C/C++ API certificate verification
---
# VOMS Server v. 2.0.14

This release provides improvements in error reporting and stronger certificate
type validation.

### Bug fixes

{% include list-rfcs.liquid %}

### New features

{% include list-features.liquid %}

### Installation and configuration

A restart of the service is needed.

For clean and update installation instructions, follow the instructions in the
[VOMS System Administrator
guide]({{site.baseurl}}/documentation/sysadmin-guide/3.0.6).
