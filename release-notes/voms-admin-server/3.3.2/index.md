---
layout: default
title: VOMS Admin server v. 3.3.2
rfcs:
    - id: VOMS-605
      title: Add ability to skip certificate issuer checks in VOMS Admin authentication
    - id: VOMS-588
      title: VOMS OrgDB sync should also update phone number for registered users
    - id: VOMS-586
      title: VOMS Admin should take user phone number from the CERN OrgDB when is defined
    - id: VOMS-585
      title: VOMS Admin should only request the user the enter his email address to search CERN OrgDB information
    - id: VOMS-564
      title: VOMS Admin should not show sensitive information taken from the HR db at registration time
    - id: VOMS-563
      title: VOMS Admin should show link to CERN phonebook when HR DB integration is enabled
---

# VOMS Admin server v. 3.3.2

This release provides minor fixes to the CERN OrgDB integration code and a new
flag that allows to skip checks on certificate issuer when doing user
authentication.

#### How to turn off certificate issuer checks

By default, VOMS Admin authenticates users considering certificate subject
**and** issuer. This means that the following certificate:

```
subject= /C=IT/O=IGI/CN=test0
issuer= /C=IT/O=IGI/CN=Test CA
```

is considered a different identity from:

```
subject= /C=IT/O=IGI/CN=test0
issuer= /C=IT/O=IGI/CN=Test CA 2
```

It is now possible to authenticate user skipping the checks on the certificate
issuer, by setting the `voms.skip_ca_check` option in a VO `service.properties`
file.

By setting the above option, the two example certificates would be considered
the same user.

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
[sysadmin-guide]:{{site.baseurl}}/documentation/sysadmin-guide/3.0.3
[voms-admin-guide]: {{site.baseurl}}/documentation/voms-admin-guide/3.3.0
