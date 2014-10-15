---
layout: post
title: Updates for several VOMS components
author: andrea
summary: New packages for VOMS core, C++ and Java APIs, VOMS Admin and VOMS clients
---

Today we release updates for all main VOMS components.
The highlights of this release are:

- [VOMS Clients 3.0.5][rn-clients] provide a new packaging which can coexist
  with the native, [2.0.12 clients][rn-clients-2x] (also released today). The
  new packaging of both packages allows the installer to choose which client
  should take precedence using the alternatives system. By default, the 3.x clients
  take precedence. The new clients also provide several bugfixes and leverage
  the latest VOMS Java APIs, as highlighted in the [release notes][rn-clients].
  Starting with this release, the clients are also available on [Maven
  Central][clients-central];

- [VOMS server 2.0.12][rn-core] which provides several bugfixes. In particular,
  some segfaults have been resolved and the server now correctly throttles
  incoming requests;

- [VOMS-Admin 3.3.0][rn-admin-server] provides bugfixes and improvements in the integration with
  the CERN Organizational Database;

- [VOMS API Java 3.0.4][rn-api-java] providing fixes for several issues.

As usual packages can be obtained from our repositories and will soon be pushed to the
EMI-3 and UMD repositories. For instructions, refer to the [download section][downloads].

This release is dedicated to the memory of our friend Valerio Venturi.

[rn-core]: {{site.baseurl}}/release-notes/voms-server/2.0.12
[rn-admin-server]: {{site.baseurl}}/release-notes/voms-admin-server/3.3.0
[rn-clients]: {{site.baseurl}}/release-notes/voms-clients/3.0.5
[rn-clients-2x]: {{site.baseurl}}/release-notes/voms-clients/2.0.12
[rn-api-java]: {{site.baseurl}}/release-notes/voms-api-java/3.0.4
[clients-central]: http://search.maven.org/#search%7Cga%7C1%7Ca%3A%22voms-clients%22
[downloads]: {{site.baseurl}}/download.html
