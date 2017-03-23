---
layout: default
title: VOMS Admin server v. 3.6.0
rfcs:
- id: VOMS-790
  title: Logback configuration runtime reloading does not work as expected
- id: VOMS-789
  title: Restore ability to configure whether VOMS Admin should require client certificates
- id: VOMS-788
  title: Concurrent execution of background tasks may have undesirable side effects
- id: VOMS-787
  title: VOMS Admin should not send AUP reminders or assign Sign AUP tasks when membership is expired
- id: VOMS-786
  title: VOMS Admin confuses clients without a certificate with non-registered authenticated clients given certain database configurations
- id: VOMS-791
  title: Migrate to the struts 2.3.32
- id: VOMS-809
  title: Migrate to Hibernate 5.2.8

---
# VOMS Admin server v. 3.6.0

This release provides fixes to some outstanding bugs and some improvements:

- Background tasks that update the VOMS database are now synchronized via a
  lock table in the database; this is useful for clustered deployments (like
  the CERN one) that have multiple active instances of the VOMS admin service
- Sign AUP reminders and notifications should not be sent to expired VO
  members
- Changes to logback configuration are now reloaded correctly at runtime

The full list of bug fixes and improvements is listed below.

### Bug fixes

{% include list-rfcs.liquid %}

### Installation and configuration

#### Upgrade from VOMS Admin Server >= 3.3.2

A [database upgrade][db-upgrade] is required to upgrade to VOMS Admin server
3.6.0. 

#### Upgrade from earlier VOMS Admin Server versions

First upgrade to VOMS Admin version [3.3.2][voms-admin-332-rn] and then to 3.6.0.

#### Clean install

Follow the instructions in the VOMS [System Administrator Guide][sysadmin-guide].

[voms-website]: http://italiangrid.github.io/voms
[sysadmin-guide]:{{site.baseurl}}/documentation/sysadmin-guide/3.0.11
[voms-admin-guide]: {{site.baseurl}}/documentation/voms-admin-guide/3.6.0
[reconf]: {{site.baseurl}}/documentation/sysadmin-guide/3.0.10/#reconf
[db-upgrade]: {{site.baseurl}}/documentation/sysadmin-guide/3.0.10/#db-upgrade
[voms-admin-332-rn]: {{site.baseurl}}/release-notes/voms-admin-server/3.3.2
