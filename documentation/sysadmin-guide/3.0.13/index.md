---
layout: default
version: 3.0.13
title: VOMS System Administrator Guide}
redirect_from:
  - /documentation/sysadmin-guide/
---

# VOMS System Administrator guide

{% include sysadmin-guide-version.liquid %}

#### Table of contents

* [Introduction](#Intro)
* [Prerequisites and recommendations](#Prereq)
* [Upgrade instructions](#Upgrade)
* [Clean installation instructions](#Installation)
* [Service configuration](configuration.html)
* [Service operation](#Operation)
* [Service migration](#Migration)
* [Troubleshooting](#Troubleshooting)

#### Other guides

{% assign ref = site.data.docs.sysadmin-guide.versions[page.version] %}

- [VOMS Services configuration reference](configuration.html)
- [VOMS Admin guides]({{site.baseurl}}/documentation/voms-admin-guide/{{ref.admin_server_version}}/index.html)

## Introduction <a name="Intro">&nbsp;</a>

The Virtual Organization Membership Service (VOMS) is an attribute authority
which serves as central repository for VO user authorization information,
providing support for sorting users into group hierarchies, keeping track of
their roles and other attributes in order to issue trusted attribute
certificates and SAML assertions used in the Grid environment for authorization
purposes.

This guide is targeted at VOMS service administrators, i.e. people installing
and running the VOMS server.

## Prerequisites and recommendations <a name="Prereq">&nbsp;</a>

### Hardware

* CPU: No specific requirements
* Memory: 2GB if serving <= 15 VOs, more otherwise
* Disk: 10/15 GB free space

### Operating system

* Supported OS: Scientific Linux 6, CENTOS 7
* NTP Time synchronization: required.
* IGTF host certificates: required.
* Networking: for the service ports see the [Service Reference Card]({{site.baseurl}}/documentation/sysadmin-guide/{{page.version}}/service-ref-card.html)

### Packages repositories

Besides the usual OS packages you will need the EPEL and UMD package
repositories configured.

All the other dependencies are resolved by the installation of the VOMS metapackages, **emi-voms-mysql**.

### Recommended deployment scenarios

A single-node installation, with the hardware recommendations given above should serve well most scenarios.
Serving a large number of VOs (> 15) will require more memory and disk space.

## Upgrade instructions <a name="Upgrade">&nbsp;</a>

See the [upgrade installation guide](upgrade-installation.html).

## Clean installation instructions<a name="Installation">&nbsp;</a>

See the [clean installation guide](clean-installation.html).

## Service operation <a name="Operation">&nbsp;</a>

See the [service operation guide](operation.html).

## Troubleshooting <a name="Troubleshooting">&nbsp;</a>

See the [known issues page]({{ site.baseurl }}/documentation/known-issues)

[voms-conf-ref]: {{site.baseurl}}/documentation/sysadmin-guide/{{page.version}}/configuration.html
[umd]: http://repository.egi.eu/category/umd_releases/distribution/umd-4/
