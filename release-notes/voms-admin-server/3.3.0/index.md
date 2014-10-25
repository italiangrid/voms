---
layout: default
title: VOMS Admin server v. 3.3.0

rfcs:
    - id: VOMS-541
      title: VOMS admin vo.d directory should live under /var/lib
    - id: VOMS-537
      title: Keep service host and bind address unrelated for VOMS Admin server
    - id: VOMS-536
      title: Disable SSLv3 in VOMS Admin
    - id: VOMS-531
      title: Handle null institute in OrgDB gracefully
    - id: VOMS-525
      title: voms-container should have workdir under /var/lib
    - id: VOMS-488
      title: Allow users to change their email address when OrgDB integration is enabled
    - id: VOMS-486
      title: voms-configure help incomplete
    - id: VOMS-458
      title: VOMS database upgrade fails when the db was created with voms-admin v. 2.5.3
    - id: VOMS-443
      title: Group manager selection should be mandatory when group managers are enabled in the registration process
    - id: VOMS-440
      title: Group and role membership notifications are not correctly dispatched to group managers
    - id: VOMS-383
      title: VOMS admin publishes wrong values for GlueServiceStatusInfo
    - id: VOMS-367
      title: VOMS Admin should bind on 0.0.0.0 by default
    - id: VOMS-294
      title: VOMS container should clean up deploy directory at start time
    - id: VOMS-292
      title: VOMS Admin SOAP registration service inconsistencies
---

# VOMS Admin server v. 3.3.0

This release provides several bug fixes and improvements for VOMS Admin server.
In particular:

- Improvements with the integration with the CERN Organizational database
- The container work directory is no more stored in /var/tmp
- VOMS Admin binds on all interfaces by default, however  a `bind_address`
  option has been added to voms-admin-server.properties to bind to specific
  interfaces
- SSLv3 support is now disabled ([CVE-2014-3566][cve-2014-3566])

### Bug fixes

{% include list-rfcs.liquid %}

### Installation and configuration

#### Clean install

Follow the instructions in the VOMS [System Administrator
Guide]({{site.baseurl}}/documentation/sysadmin-guide/3.0.1).

#### Upgrade from v. 3.2.0

The upgrade requires a service restart.
After the packages have been updated, run the following commands:

```bash
service voms-admin stop
service voms-admin undeploy
service voms-admin start
```

#### Upgrade from earlier VOMS Admin versions

Upgrading to this version requires an upgrade of the database and a
reconfiguration depending on the version of VOMS admin which is being upgraded.
Follow the instructions in the VOMS [System Administrator
Guide]({{site.baseurl}}/documentation/sysadmin-guide/3.0.1).

| Upgrade from   | Actions required                                                                                            |
| :------------: | :----------------:                                                                                          |
| v. 3.1.0       | <span class="label label-important">db upgrade</span>                                                       |
| v. 2.7.0       | <span class="label label-important">db upgrade</span> <span class="label label-info">reconfiguration</span> |


[voms-website]: http://italiangrid.github.io/voms
[voms-admin-guide]: {{site.baseurl}}/documentation/voms-admin-guide/3.3.0
[cve-2014-3566]: https://access.redhat.com/security/cve/CVE-2014-3566
