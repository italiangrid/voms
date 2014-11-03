---
layout: default
title: VOMS Admin server v. 3.3.1

rfcs:
    - id: VOMS-542
      title: VOMS Admin should allow to configure the set of supported SSL protocols and cipher suites
---

# VOMS Admin server v. 3.3.1

This release provides support for configuring enabled SSL protocols and cipher
suites. This work was motivated by the [poddle vulnerability][cve-2014-3566],
solved in v. 3.3.0 by disabling support for SSLv3. It turns out, however, that
some older clients (e.g., mkgridmap) will stop working with SSLv3 disabled, so
this release:

- does not disable SSLv3 by default;
- provides the ability to configure the set of supported enabled cipher suites and
  protocols for the SSL/TLS connectors.

#### How to disable SSLv3 in VOMS-Admin v. 3.3.1

SSLv3 can be disabled by editing the
`/etc/voms-admin/voms-admin-server.properties` configuration file to set the
`tls_exclude_protocols` property as follows:

```properties
# Comma-separated list of disabled protocols
tls_exclude_protocols=SSLv3
```

### Bug fixes

{% include list-rfcs.liquid %}

### Installation and configuration

#### Clean install

Follow the instructions in the VOMS [System Administrator
Guide]({{site.baseurl}}/documentation/sysadmin-guide/3.0.2).

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
Follow the instructions in the VOMS [System Administrator
Guide]({{site.baseurl}}/documentation/sysadmin-guide/3.0.2).

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
[voms-admin-guide]: {{site.baseurl}}/documentation/voms-admin-guide/3.3.0
[cve-2014-3566]: https://access.redhat.com/security/cve/CVE-2014-3566
