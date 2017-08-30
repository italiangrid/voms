---
layout: default
title: VOMS Admin server v. 3.7.0
rfcs:
- id: VOMS-830
  title: DNs not normalized by VOMS Admin when voms.skip_ca_check is True
- id: VOMS-812
  title: Permission cache should be cleaned up whenever interesting user related events are raised
- id: VOMS-811
  title: Serialization error leads to class cast exception when accessing user/group/role generic attributes from SOAP web service
- id: VOMS-831
  title: User provisioning API
---
# VOMS Admin server v. 3.7.0

This release provides fixes to some outstanding bugs and provides some improvements:

- DNs are now correctly normalized by VOMS Admin when voms.skip\_ca\_check is on
- Improvements in the management of the permission cache introduced in VOMS
  Admin 3.6.0
- Improved REST API to query VOMS user information, documented in the [voms admin guide][voms-admin-guide-api]

The full list of bug fixes and improvements is listed below.

### Bug fixes and enhancements

{% include list-rfcs.liquid %}

### Installation and configuration

#### Upgrade from VOMS Admin Server 3.6.0

A service restart is required for changes to take effect.

#### Upgrade from VOMS Admin Server >= 3.3.2 

A [database upgrade][db-upgrade] is required to upgrade to VOMS Admin server
3.7.0. 

#### Upgrade from earlier VOMS Admin Server versions

First upgrade to VOMS Admin version [3.3.2][voms-admin-332-rn] and then to 3.7.0.

#### Clean install

Follow the instructions in the VOMS [System Administrator Guide][sysadmin-guide].

[voms-website]: http://italiangrid.github.io/voms
[sysadmin-guide]:{{site.baseurl}}/documentation/sysadmin-guide/3.0.12
[voms-admin-guide-api]: {{site.baseurl}}/documentation/voms-admin-guide/3.7.0/api.html
[reconf]: {{site.baseurl}}/documentation/sysadmin-guide/3.0.11/#reconf
[db-upgrade]: {{site.baseurl}}/documentation/sysadmin-guide/3.0.11/#db-upgrade
[voms-admin-332-rn]: {{site.baseurl}}/release-notes/voms-admin-server/3.3.2
[VOMS-790]: https://issues.infn.it/jira/browse/VOMS-790
