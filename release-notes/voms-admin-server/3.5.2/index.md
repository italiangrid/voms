---
layout: default
title: VOMS Admin server v. 3.5.2
rfcs:
  - id: VOMS-792
    title: NPE raised when running MembershipCheck Task 
---

# VOMS Admin server v. 3.5.2

This release provides a fix for the unsafe handling of membership that do not
expire, which caused failures during the execution of the background task that
checks membership status and could lead to incorrect behaviour. 

### Bug fixes

{% include list-rfcs.liquid %}

### Installation and configuration

#### Upgrade from VOMS Admin Server 3.5.0

A service restart is required for the changes to take effect.

#### Upgrade from VOMS Admin Server >= 3.3.2

A [database upgrade][db-upgrade] is required to upgrade to VOMS Admin server 3.5.2.

#### Upgrade from earlier VOMS Admin Server versions

First upgrade to VOMS Admin version [3.3.2][voms-admin-332-rn] and then to 3.5.2.

#### Clean install

Follow the instructions in the VOMS [System Administrator Guide][sysadmin-guide].

[voms-website]: http://italiangrid.github.io/voms
[sysadmin-guide]:{{site.baseurl}}/documentation/sysadmin-guide/3.0.10
[voms-admin-guide]: {{site.baseurl}}/documentation/voms-admin-guide/3.5.2
[reconf]: {{site.baseurl}}/documentation/sysadmin-guide/3.0.10/#reconf
[db-upgrade]: {{site.baseurl}}/documentation/sysadmin-guide/3.0.10/#db-upgrade
[voms-admin-332-rn]: {{site.baseurl}}/release-notes/voms-admin-server/3.3.2
