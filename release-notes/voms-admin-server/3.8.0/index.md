---
layout: default
title: VOMS Admin server v. 3.8.0
rfcs:
- id: VOMS-869
  title: https://issues.infn.it/jira/browse/VOMS-869
- id: VOMS-832
  title: Duplicate entries in membership expiration warning
- id: VOMS-833
  title: Fix typo in membership expiration warning email
- id: VOMS-834
  title: Wrong struts validation configuration makes audit log search unusable
- id: VOMS-836
  title: Bulk extend membership button do not work as expected in VOMS admin 3.7.0
- id: VOMS-856
  title: Adapt VOMS Admin to CERN HR GDPR changes
- id: VOMS-874
  title: Remove certificate fails when invoked from the SOAP API
---
# VOMS Admin server v. 3.8.0

The release provides many bug fixes and improvements:

- CENTOS 7/SystemD porting: VOMS Admin is now ported to CENTOS 7 and runs on
  SystemD; see the [VOMS system administrator guide][sysadmin-guide] for more
  details;
- GDPR compliance changes: VOMS Admin now hides sensitive information by
  default 
- Dependency upgrades: 
  - Struts upgrade to version 2.5.22
  - MySQL connector upgrade to version 8.0.16
- New CERN HR integration code

The full list of bug fixes and improvements is listed below.

### Bug fixes and enhancements

{% include list-rfcs.liquid %}

### Installation and configuration

#### Upgrade from VOMS Admin Server 3.6.0

A service restart is required for changes to take effect.

#### Clean install

Follow the instructions in the VOMS [System Administrator Guide][sysadmin-guide].

[voms-website]: http://italiangrid.github.io/voms
[sysadmin-guide]:{{site.baseurl}}/documentation/sysadmin-guide/3.0.12
[voms-admin-guide-api]: {{site.baseurl}}/documentation/voms-admin-guide/3.8.0/api.html
[reconf]: {{site.baseurl}}/documentation/sysadmin-guide/3.0.11/#reconf
[db-upgrade]: {{site.baseurl}}/documentation/sysadmin-guide/3.0.11/#db-upgrade
[voms-admin-332-rn]: {{site.baseurl}}/release-notes/voms-admin-server/3.3.2
[VOMS-790]: https://issues.infn.it/jira/browse/VOMS-790
