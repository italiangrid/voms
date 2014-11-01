---
layout: default
title: VOMS C/C++ APIs v. 2.0.12-2
rfcs:
    - id: VOMS-543
      title: VOMS spec file does not set build dependency on gSoap devel
---

# VOMS C/C++ APIs v. 2.0.12-2


This release fixes an issue in the VOMS packaging that caused build failures
with mock by adding a build-time dependency on gSoap-devel that was
previously missing.

### Bug fixes

{% include list-rfcs.liquid %}

### Installation and configuration

For clean and update installation instructions, follow the instructions in the
[VOMS System Administrator
guide]({{site.baseurl}}/documentation/sysadmin-guide/3.0.2).
