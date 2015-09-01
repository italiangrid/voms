---
layout: post
title: VOMS Admin server v. 3.3.4
author: andrea
summary: Several fixes and improvements for VOMS Admin server
---

This release provides an update for VOMS Admin server.

[VOMS Admin server 3.3.4][rn-admin] provides several features and improvements,
here is a list of the main changes:

- all actions performed are now saved in a persistent audit log in the voms
  database; this audit log replaces the limited request log available in former
  voms-admin releases;

- improved request handling page that allows to handle multiple requests with a
  single click;

- the CERN HR member id is leveraged instead of the primary email address for
  linking VOMS and CERN HR membership;

- VOMS admin RPM now depend on Java 8;

For more details, see the [release notes][rn-admin].

As usual packages can be obtained from our repositories and will soon be pushed
to the EMI-3 and UMD repositories. For instructions, refer to  the [releases
section][releases].

[rn-admin]: {{site.baseurl}}/release-notes/voms-admin-server/3.3.4
[releases]: {{site.baseurl}}/releases.html
