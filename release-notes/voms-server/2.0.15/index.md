---
layout: default
title: VOMS Server v. 2.0.15
rfcs:
- id: VOMS-866
  title: Port VOMS server and APIs to CENTOS 7
- id: VOMS-880
  title: Merge OSG patches
---
# VOMS Server v. 2.0.15

### Bug fixes & new features

{% include list-rfcs.liquid %}

### Installation and configuration

A restart of the service is needed.

On CENTOS 7, VOMS is now managed with SystemD as an instantiated service. For
more details, see the [VOMS system administrator guide][sysadmin-guide].


[sysadmin-guide]: {{site.baseurl}}/documentation/sysadmin-guide/3.0.13/
