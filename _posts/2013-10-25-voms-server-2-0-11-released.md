---
layout: post
title: VOMS Server v. 2.0.11 
author: andrea
summary: The new VOMS server fixes a socket handling issue
---

The VOMS Product Team is pleased to announce the release of VOMS Server v. 2.0.11.

This release fixes an issue in the handling of very slow or malicious clients
that could lead to an endless loop in the VOMS server socket accept procedure.

More details in the [release notes][rel-notes-server].  Packages can be obtained from our
repositories and will soon be available on the EMI-3 repository. Follow the
instructions in the [download section][downloads].

**N.B.**: Also C/C++ API packages and the legacy 2.x voms-client packages see their version change
even if no changes affect those packages. 

[rel-notes-server]: {{site.baseurl}}/release-notes/voms-server/2.0.11
[downloads]: {{site.baseurl}}/download.html
