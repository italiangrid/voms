---
layout: default
title: VOMS Server v. 2.0.16
rfcs:
- id: VOMS-913
  title: Fix broken SystemD unit for the VOMS server
---
# VOMS Server v. 2.0.16

### Bug fixes & new features

{% include list-rfcs.liquid %}

### Installation and configuration

A restart of the service is needed.

On CENTOS 7, VOMS is now managed with SystemD as an instantiated service. For
more details, see the [VOMS system administrator guide][sysadmin-guide].

[sysadmin-guide]: {{site.baseurl}}/documentation/sysadmin-guide/3.0.14/
