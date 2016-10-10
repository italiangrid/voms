---
layout: default
title: VOMS Admin server v. 3.5.1
rfcs:
  - id: VOMS-768
    title: Unsafe handling of empty strings in the audit event addDataPoint method
---

# VOMS Admin server v. 3.5.1

This release provides a fix for the unsafe handling of empty strings that could
lead to failures in generating audit event logs and prevent the correct
delivery of some notifications (e.g., Sign AUP notifications).

### Bug fixes

{% include list-rfcs.liquid %}

### Installation and configuration

#### Upgrade from VOMS Admin Server 3.5.0

A service restart is required for the changes to take effect.

#### Upgrade from VOMS Admin Server >= 3.3.2

A [database upgrade][db-upgrade] is required to upgrade to VOMS Admin server 3.5.1.

#### Upgrade from earlier VOMS Admin Server versions

First upgrade to VOMS Admin version [3.3.2][voms-admin-332-rn] and then to 3.5.1.

#### Clean install

Follow the instructions in the VOMS [System Administrator Guide][sysadmin-guide].

[voms-website]: http://italiangrid.github.io/voms
[sysadmin-guide]:{{site.baseurl}}/documentation/sysadmin-guide/3.0.9
[voms-admin-guide]: {{site.baseurl}}/documentation/voms-admin-guide/3.5.1
[reconf]: {{site.baseurl}}/documentation/sysadmin-guide/3.0.9/#reconf
[db-upgrade]: {{site.baseurl}}/documentation/sysadmin-guide/3.0.9/#db-upgrade
[voms-admin-332-rn]: {{site.baseurl}}/release-notes/voms-admin-server/3.3.2
