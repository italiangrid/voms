---
layout: default
version: 3.0.13
title: VOMS clean installation
---

# VOMS clean installation

{% include sysadmin-guide-version.liquid %}

## Repository configuration

See the [repository configuration instructions][repo-config].

### Recommended deployment scenarios

A single-node installation, with the hardware recommendations given above
should serve well most scenarios. Serving a large number of VOs (> 15) will
require more memory and disk space.

## Clean installation instructions<a name="clean-installation">&nbsp;</a>

These are the full instructions for a clean installation.

### Repositories

See the instructions [above](#Repository).

### Certificate revocation lists

You need EGI IGTF certification authorities certificates installed and the `fetch-crl` cron job enabled:

```bash
yum -y install ca-egi-policy-core fetch-crl
```

and enable a cron job that periodically refresh CRLs as follows:

```bash
/sbin/chkconfig fetch-crl-cron on
/sbin/service fetch-crl-cron start
```
### Clean installation

Install the `emi-voms-mysql` metapackage:

```bash
yum install emi-voms-mysql
```

## Configuration instructions <a name="Configuration">&nbsp;</a>

This section provides information on how to configure the VOMS services and the
services VOMS depends on (e.g., mysql). VOMS configuration is bootstrapped
using its own configuration script, *voms-configure*. 

A reference of VOMS services configuration files can be found in the [VOMS
Services Configuration reference][voms-conf-ref].

### Database backend configuration

#### MySQL

Make sure that the MySQL administrator password that you specify when running
`voms-configure` matches the password that is set for the root MySQL account,
as `voms-configure` will not set it for you. 

Ensure that MySQL is running. If not running, start it (as root) using the
following command:

```
# service mysqld start (SL6)
```

```
# systemd start mariadb (CENTOS 7)
```

The following commands change the password for the MySQL/MariaDB root account:

```bash
/usr/bin/mysqladmin -u root password <adminPassword>
/usr/bin/mysqladmin -u root -h <hostname> password <adminPassword>
```

### Configuring the VOMS Admin container

See the instructions [above](#ContainerConf).

### VOMS services configuration

Run `voms-configure` to configure VOs for both voms-admin and voms. The general syntax of the command is

```bash
voms-configure COMMAND [OPTIONS]
```

Available commands are:

* `install` is used to configure a VO
* `remove`: is used to remove a VO configuration
* `upgrade`: is used to upgrade the configuration of a VO installed with an older version of voms-admin.

Usually, you do not have a dedicated MySQL administrator working for you, so you will use voms-admin tools to create the database schema, configure the accounts and deploy the voms database. If this is the case, you need to run the following command:


```bash
voms-configure install --vo <vo name> \
--dbtype mysql \
--createdb \
-–deploy-database \
--dbauser <mysql root admin  username> \
--dbapwd <mysql root admin  password> \
--dbusername <mysql voms username> \
--dbpassword  <mysql voms password> \
--core-port <voms core service port> \
--smtp-host <STMP relay host> \
--mail-from <Sender address for service-generated emails>
```

Note that the above command is entered as a single command; it has been broken up into multiple lines for clarity.
The command creates and initializes a VOMS database, and configures the VOMS core and admin services that use such database. 
For more information about `voms-configure` options, see the man page.

An example MySQL VO installation command is shown below:

```bash
voms-configure install --vo test.vo \
--dbtype mysql --createdb --deploy-database \
--dbauser root --dbapwd pwd \
--dbusername voms --dbpassword pwd \ 
--core-port 15000 \
--mail-from ciccio@cnaf.infn.it \ 
--smtp-host iris.cnaf.infn.it
```

`voms-configure` is used also for removing already configured vos

```bash
voms-configure remove --vo VONAME
```

Available options are:

* undeploy-database:	 Undeploys the VOMS database. By default when removing a VO the database is left untouched. All the database content is lost.
* dropdb (MySQL only):	 This flag is used to drop the mysql database schema created for MySQL installations using the --createdb option

See the `voms-configure` help for a list of all the supported options and their meaning.

[voms-conf-ref]: {{site.baseurl}}/documentation/sysadmin-guide/{{page.version}}/configuration.html
[repo-config]: {{site.baseurl}}/documentation/sysadmin-guide/{{page.version}}/repositories.html
[egi-trustanchors]: https://wiki.egi.eu/wiki/EGI_IGTF_Release
[umd]: https://repository.egi.eu/category/umd_releases/distribution/umd-4/
