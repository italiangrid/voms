---
layout: default
title: VOMS Admin server v. 3.4.0
rfcs:
- id: VOMS-524
  title: Include Orgdb configuration documentation in VOMS administrator guide
- id: VOMS-625
  title: Cumulative permissions do not grant all intended privileges
- id: VOMS-628
  title: VOMS Admin pending request page should provide easy access to requestor email address
- id: VOMS-629
  title: Improve VOMS Admin request certificate page
- id: VOMS-631
  title: VOMS Admin RPM should depend on Java 8
- id: VOMS-636
  title: VOMS admin change reacceptance period should be protected by a confirmation dialog
- id: VOMS-640
  title: VOMS Admin sessions expire in two minutes
- id: VOMS-645
  title: Force users to include a textual motivation for group and role requests
features:
- id: VOMS-129
  title: VOMS admin provides configurable notification interval for Sign AUP messages
- id: VOMS-633
  title: Add ability to handle multiple requests page from VOMS Admin "Handle requests" page
- id: VOMS-634
  title: VOMS Admin handle request page should show only requests that can be handled by an administrator
- id: VOMS-635
  title: VOMS triggerReacceptance confirm dialog should shield from user mistakes
- id: VOMS-649
  title: Add ability to edit group description
- id: VOMS-650
  title: VOMS should leverage HR member id instead of primary email for linking VOMS and HR membership
- id: VOMS-654
  title: VOMS should provide a page that displays detailed information about the certificate used to connect to the service
- id: VOMS-655
  title: Group-Manager role to grant group membership request rights
---

# VOMS Admin server v. 3.4.0

This release

- fixes ...

- introduces new features:

  - [Configure multiple AUP re-sing reminders][VOMS-129]
  - [Handle multiple requests via a single click][VOMS-633]
  - [Audit log for relevant events][VOMS-637]
  - [VOMS and external HR database linked through HR member id][VOMS-650]
  - [Authenticated users's detail page][VOMS-654]
  - [Users with Group-Manager role can handle group membership requests][VOMS-655]

### Bug fixes

{% include list-rfcs.liquid %}

### Improvements

{% include list-features.liquid %}

### Installation and configuration

#### Clean install

Follow the instructions in the VOMS [System Administrator Guide][sysadmin-guide].

#### Upgrade from v. >= 3.2.0

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
Follow the instructions in the VOMS [System Administrator Guide][sysadmin-guide].

| Upgrade from   | Actions required                                                                                            |
| :------------: | :----------------:                                                                                          |
| v. 3.1.0       | <span class="label label-important">db upgrade</span>                                                       |
| v. 2.7.0       | <span class="label label-important">db upgrade</span> <span class="label label-info">reconfiguration</span> |


{% if site.versions.services.voms-admin-server.previous %}
# Previous versions

<ul>
{% for v in site.versions.services.voms-admin-server.previous %}
  <li><a href="{{site.baseurl}}/release-notes/voms-admin-server/{{v}}" >{{v}}</a></li>
{% endfor %}
</ul>
{% endif %}


[voms-website]: http://italiangrid.github.io/voms
[sysadmin-guide]:{{site.baseurl}}/documentation/sysadmin-guide/3.0.5
[voms-admin-guide]: {{site.baseurl}}/documentation/voms-admin-guide/3.4.0

[VOMS-129]: {{site.baseurl}}/release-notes/voms-admin-server/3.4.0/features/voms-129/index.html
[VOMS-633]: {{site.baseurl}}/release-notes/voms-admin-server/3.4.0/features/voms-633/index.html
[VOMS-637]: {{site.baseurl}}/release-notes/voms-admin-server/3.4.0/features/voms-637/index.html
[VOMS-650]: {{site.baseurl}}/release-notes/voms-admin-server/3.4.0/features/voms-650/index.html
[VOMS-654]: {{site.baseurl}}/release-notes/voms-admin-server/3.4.0/features/voms-654/index.html
[VOMS-655]: {{site.baseurl}}/release-notes/voms-admin-server/3.4.0/features/voms-655/index.html
