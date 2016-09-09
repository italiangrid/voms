---
layout: default
title: VOMS Service Reference Card
version: 3.0.8
---

# VOMS Service Reference Card

{% include sysadmin-guide-version.liquid %}

#### Table of contents
* [Functional Description](#funcdesc)
* [Daemons Running](#daemons)
* [Init scripts and options](#scripts)
* [Configuration files location with example or template](#conffiles)
* [Logfile locations and other useful audit information](#logfiles)
* [Open ports](#ports)
* [Where is service state held (and can it be rebuilt)](#state)
* [Cron jobs](#crons)
* [Security information](#security)
* [Utility scripts](#utility)
* [Location of reference documentation for users and administrators](#docs)


## Functional description <a name="funcdesc">&nbsp;</a>

The Virtual Organization Membership Service (VOMS) is an attribute authority which serves as central repository for VO user authorization information, providing support for sorting users into group hierarchies, keeping track of their roles and other attributes in order to issue trusted attribute certificates and SAML assertions used in the Grid environment for authorization purposes.

VOMS is composed of two main components:

* the VOMS core service, which issues attribute certificates to authenticated clients 
* the VOMS Admin service, which is used by VO manager to administer VOs and manage user membership details.

## Daemons running <a name="daemons">&nbsp;</a>

The following daemons need to be running:

* voms-admin
* voms
* mysql (in case of MySQL is running directly on the VOMS server)

## Init scripts and options <a name="scripts">&nbsp;</a>

For the _voms_ service

```bash
service voms start
service voms status
service voms stop
```

For the _voms-admin_ service

```bash
service voms-admin start
service voms-admin status
service voms-admin stop
```

## Configuration files location with example or template <a name="conffiles">&nbsp;</a>

The configuration files are located in:

* `/etc/voms/`
* `/etc/voms-admin/`

## Logfile locations and other useful audit information <a name="logfiles">&nbsp;</a>

The log files can be found under 

* `/var/log/voms`
* `/var/log/voms-admin`

## Open ports <a name="ports">&nbsp;</a>

The following ports need to be open depending on the services running:

* `voms`: one for each vo, tipically 1500x
* `voms-admin`: one, tipycally 8443

## Where is service state held (and can it be rebuilt) <a name="state">&nbsp;</a>

The VOMS service state is kept in the VOMS database. Location and access information for the database can be found in the configuration files.

## Cron jobs <a name="crons">&nbsp;</a>

VOMS relies only on the fetch-crl cron job being active. There are no other VOMS specific cron jobs.

## Security information <a name="security">&nbsp;</a>

### Access control Mechanism description (authentication & authorization)

This node type has two interfaces. One for the administration where VO admins can add/remove users and assign VO Roles and a second one where the middleware applications ask for proxy signature. On both interfaces the authentication part is done via x509 authentication against the trusted CAs that are installed at the node. The authorization part is done via the VO roles that are assigned to the uses's DN.

### How to block/ban a user

It is possible to fine tune access rules to the VOMS administrator services using Access Control Lists. See the VOMS Admin user's guide for more information on this. Note that however it is safe to leave read access on to any authenticated client, as this functionality it is still used to create gridmap files for some middleware components. The access to the proxy signature interface is limited to the users that are listed as active members to the VO. Removing a user from the VO, or suspending his membership, will block his/her ability to obtain a valid proxy signature from the VOMS server. See the VOMS Admin user's guide for more information on how to remove and suspend users in a VO.

### Network Usage

Three services are running that need network access on this node-type.

* the MySQL server service. The server binds to the 3306/tcp port. Alternatively, Oracle may be used, which is usually run on a different node. Access to this node should be allowed.
* the `voms-admin` server which binds at one tcp port (typically 8443/tcp)  
* the `voms` server which binds to one tcp port per VO (usually something like 15010/tcp)

### Firewall configuration

See [Open ports](#ports).

### Security recommendations

None.

###  Security incompatibilities

None.

### Other security relevant comments

This node-type SHOULD NOT be co-located with any other node-type and should not allow shell access to users. Any connection other than the ones described above should be treated as suspicious.


## Utility scripts <a name="utility">&nbsp;</a>

* voms-admin (client & server side)
* voms-proxy-* (client side)
* voms-db-util (server side)
* voms-mysql-util (server side)
* voms-configure (server side)
* voms-config-info-provider (server side)

## Location of reference documentation for users and administrators <a name="docs">&nbsp;</a>

* [VOMS documentation]({{site.baseurl}}/documentation.html)
