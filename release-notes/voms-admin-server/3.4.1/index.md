---
layout: default
title: VOMS Admin server v. 3.4.1
rfcs:
  - id: VOMS-678
    title: VOMS Admin skip-ca check does not work as expected for unprivileged VOMS Admin users
  - id: VOMS-705
    title: Extend membership expiration time at each sync for VO members with valid, open-ended experiment participation
  - id: VOMS-706
    title: Add the ability to disable membership expiration notifications
  - id: VOMS-707
    title: Trim whitespace and remove newlines from subject in certificate requests
---

# VOMS Admin server v. 3.4.1

#### Authenticate users by certificate subject

Now users are correctly authenticated by certificate subject. With default
settings, VOMS Admin authenticates clients by looking at the client certificate
(subject,issuer) couple. A configuration flag was introduced in VOMS Admin
3.3.2 to authenticate only by certificate subject, but the fix worked only for
VO administrators. This  problem is now fixed. 

For instruction on how to enable this feature, see the VOMS Admin
[3.3.2][voms-admin-332-rn] release notes.

#### Disable membership expiration notifications

Is now possible to disable membership expiration notifications. This kind of
notification do not make sense in deployments, like at CERN, where a VO administrator
cannot extend the lifetime of VO members.

To disable membership expiration notifications either:

- reconfigure the affected VO with `voms-configure` specifying the `--disable-membership-expiration-warnings` option
- set the `voms.membership.disable_expiration_warning` in `/etc/voms-admin/<VO>/service.properties`

A restart of the service is required.

Other improvements and fixes are listed below.

### Bug fixes

{% include list-rfcs.liquid %}

### Installation and configuration

#### Upgrade from VOMS Admin Server 3.4.0

Update the packages and restart the service.

#### Upgrade from VOMS Admin Server >= 3.2.0

A [database upgrade][db-upgrade] and a [reconfiguration][reconf] (in this order) are
required to upgrade to VOMS Admin server 3.4.1.

#### Upgrade from earlier VOMS Admin Server versions

First upgrade to VOMS Admin version [3.2.0][voms-admin-320-rn] and then to 3.4.1.

#### Clean install

Follow the instructions in the VOMS [System Administrator Guide][sysadmin-guide].

[voms-website]: http://italiangrid.github.io/voms
[sysadmin-guide]:{{site.baseurl}}/documentation/sysadmin-guide/3.0.6
[voms-admin-guide]: {{site.baseurl}}/documentation/voms-admin-guide/3.4.1
[reconf]: {{site.baseurl}}/documentation/sysadmin-guide/3.0.6/#reconf
[db-upgrade]: {{site.baseurl}}/documentation/sysadmin-guide/3.0.6/#db-upgrade
[voms-admin-320-rn]: {{site.baseurl}}/release-notes/voms-admin-server/3.2.0
[voms-admin-332-rn]: {{site.baseurl}}/release-notes/voms-admin-server/3.3.2
