---
layout: default
title: VOMS Admin server v. 3.3.3
rfcs:
- id: VOMS-609
  title: Removing a user causes the removal of all pending requests
- id: VOMS-608
  title: VOMS Admin does not handle correctly multiple VO membership request
- id: VOMS-607
  title: Mandatory Group manager selection should be configurable
- id: VOMS-606
  title: VOMS should refer to Institute.name instead of Institute.originalName when populating institution field from the CERN HR  DB
---

# VOMS Admin server v. 3.3.3

This release

- fixes a problem that caused the removal of all pending requests if a user was
  removed from the VOMS database
- fixes a problem in the handling of multiple VO membership requests
- introduces the `voms.request.vo_membership.require_group_manager_selection`
  configuration flag to enable/disable the mandatory selection of a group manager
  (GM) by applicants at VO registration time. By default, GM selection is
  mandatory.

### Bug fixes and improvements

{% include list-rfcs.liquid %}

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
[sysadmin-guide]:{{site.baseurl}}/documentation/sysadmin-guide/3.0.4
[voms-admin-guide]: {{site.baseurl}}/documentation/voms-admin-guide/3.3.0
