---
layout: default
title: VOMS Admin server v. 3.8.1
rfcs:
- id: VOMS-883
  title: HR db sync task is not started even when the `membership_check.enabled=true` property is set
- id: VOMS-887
  title: Update struts dependency to 2.5.26
---
# VOMS Admin server v. 3.8.1

### Bug fixes and enhancements

{% include list-rfcs.liquid %}

### Installation and configuration

A service restart is required for changes to take effect.

#### Clean install

Follow the instructions in the VOMS [System Administrator Guide][sysadmin-guide].

[voms-website]: http://italiangrid.github.io/voms
[sysadmin-guide]:{{site.baseurl}}/documentation/sysadmin-guide/3.0.13
[voms-admin-guide-api]: {{site.baseurl}}/documentation/voms-admin-guide/3.8.1/api.html
[reconf]: {{site.baseurl}}/documentation/sysadmin-guide/3.0.11/#reconf
[db-upgrade]: {{site.baseurl}}/documentation/sysadmin-guide/3.0.11/#db-upgrade
[voms-admin-332-rn]: {{site.baseurl}}/release-notes/voms-admin-server/3.3.2
[VOMS-790]: https://issues.infn.it/jira/browse/VOMS-790
