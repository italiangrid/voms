---
layout: default
title: VOMS Admin server v. 3.4.2
rfcs:
  - id: VOMS-710
    title: User requests cannot be approved if Group-Manager role is not defined
  - id: VOMS-711
    title: VOMS Admin sign-aup URL broken
---

# VOMS Admin server v. 3.4.2

This release provides fixes to a couple of problems introduced in VOMS Admin
3.4.0, in particular:

- The handling of group-scoped user requests was broken if the "Group-Manager"
  role was not defined for a VO
- The sign-aup alias URL sent in user suspension notifications was broken

### Bug fixes

{% include list-rfcs.liquid %}

### Installation and configuration

#### Upgrade from VOMS Admin Server >= 3.4.0

Update the packages and restart the service.

#### Upgrade from VOMS Admin Server >= 3.2.0

A [database upgrade][db-upgrade] and a [reconfiguration][reconf] (in this order) are
required to upgrade to VOMS Admin server 3.4.2.

#### Upgrade from earlier VOMS Admin Server versions

First upgrade to VOMS Admin version [3.2.0][voms-admin-320-rn] and then to 3.4.2.

#### Clean install

Follow the instructions in the VOMS [System Administrator Guide][sysadmin-guide].

[voms-website]: http://italiangrid.github.io/voms
[sysadmin-guide]:{{site.baseurl}}/documentation/sysadmin-guide/3.0.6
[voms-admin-guide]: {{site.baseurl}}/documentation/voms-admin-guide/3.4.2
[reconf]: {{site.baseurl}}/documentation/sysadmin-guide/3.0.6/#reconf
[db-upgrade]: {{site.baseurl}}/documentation/sysadmin-guide/3.0.6/#db-upgrade
[voms-admin-320-rn]: {{site.baseurl}}/release-notes/voms-admin-server/3.2.0
[voms-admin-332-rn]: {{site.baseurl}}/release-notes/voms-admin-server/3.3.2
