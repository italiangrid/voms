---
layout: post
title: Updates for several VOMS components 
author: andrea
summary: New packages for VOMS server, C/C++ APIs, VOMS Admin, VOMS clients and VOMS MySQL plugin
---

Today we announce a new release for several VOMS components fixing outstanding
bugs and providing new features.

The updated components are:

- [VOMS Admin 3.5.0][rn-admin]: which fixes problems found in the former releases
  and introduces new features. More details in the [release notes][rn-admin]
- [VOMS clients 3.0.7][rn-clients]: starting from this release voms-proxy-init
  generates RFC proxies by default
- [VOMS C/C++ APIs 2.0.14][rn-api-c]: which provide improved certificate
  chain type detection and validation, mainly targeted at support for RFC proxy
  certificate chains
- [VOMS server 2.0.14][rn-core]: which provides improved certificate validation
  error reporting 
- [VOMS MySQL plugin 3.1.7][rn-mysql-plugin]: which fixes a problem with data
  types used in some queries which caused improper logging of user IDs in VOMS
  server logs

As usual, packages can be obtained from our repositories and will soon be
pushed to UMD repositories. For instructions, refer to  the [releases
section][releases].

[rn-admin]: {{site.baseurl}}/release-notes/voms-admin-server/3.5.0
[rn-clients]: {{site.baseurl}}/release-notes/voms-clients/3.0.7
[rn-api-c]: {{site.baseurl}}/release-notes/voms-api-c/2.0.14
[rn-core]: {{site.baseurl}}/release-notes/voms-server/2.0.14
[rn-mysql-plugin]: {{site.baseurl}}/release-notes/voms-mysql-plugin/3.1.7

[releases]: {{site.baseurl}}/releases.html
