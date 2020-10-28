---
layout: default
version: 3.0.13
title: VOMS services configuration reference
---

# VOMS services configuration reference

{% include sysadmin-guide-version.liquid %}

#### Table of contents

- [VOMS Configuration files](#voms_configuration_files)
- [VOMS server configuration](#voms_server_configuration)
  - [/etc/sysconfig/voms](#etc_sysconfig_voms)
  - [VOMS Server VO configuration](#voms_vo_conf)
- [VOMS Admin configuration](#voms_admin_configuration)
  - [/etc/sysconfig/voms-admin](#etc_sysconfig_voms_admin)
  - [Container configuration](#container_conf)
  - [VOMS Admin VO configuration](#voms_admin_vo_conf)
  - [CERN HR plugin configuration](#cern_hr)
- [Configuration utilities](#config_utils)
- [Information system configuration](#info-system)
- [Troubleshooting](#troubleshooting)


## VOMS configuration files <a name="voms_configuration_files"></a>

The VOMS server configuration lives in the `/etc/voms/<VO_NAME>` directory and is composed of two files:

- *voms.conf*, which contains the configuration for the server
- *voms.pass*, which contains the password to access the database

The VOMS Admin container configuration lives in the `/etc/voms-admin` directory and consists of the following files:

- *voms-admin-server.properties*, which contains the main service configuration (host, port, certificates)
- *voms-admin-server.logback*, which contains the logging configuration for the server

The VOMS Admin VO configuration lives in the `/etc/voms-admin/<VO_NAME>` direcotory and is composed
of the following files:

- *service.properties*, which contains the main VO configuration
- *database.properties*, which contains database access and connection pool configuration for the VO
- *logback.xml*, which controls logging of the VO application

## VOMS server configuration <a name="voms_server_configuration"></a>

### /etc/sysconfig/voms <a name="etc_sysconfig_voms"></a>

This file contains variables needed by startup scripts to properly execute the VOMS service

| Property | Description | Default value |
|:--------:|:-----------:|:-------------:|
| `VOMS_USER` | The user under which the VOMS process will run | `voms` |
| `TNS_ADMIN` | Default oracle tnsnames.ora location | `/etc/voms` |

### VOMS server VO configuration <a name="voms_vo_conf"></a>

The VOMS server configuration for a VO can be found in `/etc/voms/VO_NAME` and is composed of two files:

- `voms.conf` containing the server configuration
- `voms.pass` containing the password used to access the database

### /etc/voms/<span class="vo-highlight">vo</span>/voms.conf  <a name="voms_conf"></a>

The server configuration file is a text file containing a series of command line options that is parsed by the VOMS
daemon at startup time. Check the VOMS man page for more information, using the following command:

```bash
man voms
```

An example VOMS configuration file:

```bash
--x509_user_cert=/etc/grid-security/vomscert.pem
--x509_user_key=/etc/grid-security/vomskey.pem
--dbname=voms_mysql
--contactstring=localhost
--username=voms-admin
--logfile=/var/log/voms/voms.mysql
--loglevel=4
--logtype=7
--passfile=/etc/voms/mysql/voms.pass
--port=18001
--code=18001
--sqlloc=/usr/lib64/libvomsmysql.so
--vo=mysql
--uri=wilco.cnaf.infn.it:18001
--timeout=86400
--socktimeout=60
--max-reqs=50
```

Special configuration flags:

| Flag            | Description                                                                        | Default  |
| :--             | :--                                                                                | :--      |
| `--skipcacheck` | Configures VOMS to only consider a certificate subject when checking VO membership | disabled |
| `--shortfqans`  | Configures VOMS to use the short fqans syntax                                      | disabled |
| `--syslog`      | Configures VOMS to log to syslog                                                   | disabled |

### /etc/voms/<span class="vo-highlight">vo</span>/voms.pass <a name="voms_pass"></a>

This is a text file containing the password used by the VOMS server to connect to the database.

# VOMS Admin configuration <a name="voms_admin_configuration"></a>


### /etc/sysconfig/voms-admin  <a name="etc_sysconfig_voms_admin"></a>

This file contains variables needed by startup scripts to properly execute the VOMS Admin services

| Property | Description | Default value |
|:---------|:------------|:--------------|
| `PREFIX` | The prefix for the VOMS Admin installation | `/` |
| `CONF_DIR` | The path where VOMS Admin configuration files are located | `/etc/voms-admin` |
| `VOMS_USER` |  The user under which the VOMS Admin process will run | `voms` |
| `ORACLE_LIBRARY_PATH` | The path to oracle native libraries | `/usr/lib64/oracle/11.2.0.3.0/client/lib64` |
| `TNS_ADMIN` | Default oracle tnsnames.ora location | `/etc/voms` |


## Container configuration <a name="container_conf"></a>


VOMS Admin container configuration can be found in the `/etc/voms-admin` directory.
The container configuration consists of two files:

- `voms-admin-server.properties`
- `voms-admin-server.logback`

### /etc/voms-admin/voms-admin-server.properties <a name="admin_server_props"></a>


This is a standard Java properties file.

| Property                       | Description                                                                         | Default value                             |
| :---------                     | :------------                                                                       | :--------------                           |
| `host`                         | The hostname where service is accepting requests                                    | The output of `hostname -f`               |
| `bind_address`                 | The address that the service will bind to. By default VOMS binds on all interfaces. | This option is usually commented out.     |
| `port`                         | The port where the service will be accepting requests                               | 8443                                      |
| `cert`                         | The service PEM encoded X.509 certificate                                           | `/etc/grid-security/vomscert.pem`         |
| `key`                          | The service private key                                                             | `/etc/grid-security/vomskey.pem`          |
| `trust_anchors.dir`            | The trust anchors directory, i.e. where CA certificates and CRLs will be looked for | `/etc/grid-security/certificates`         |
| `trust_anchors.refresh_period` | How ofter trust anchors are refreshed from the trust anchors dir (in seconds)       | 3600 (i.e. every hour)                    |
| `max_connections`              | Maximum number of concurrent connections accepted by the service                    | 50                                        |
| `max_request_queue_size`       | Maximum number of client requests queued                                            | 200                                       |
| `tls_exclude_protocols`        | The list of disabled SSL/TLS protocols                                              | This option is commented out by default.  |
| `tls_include_protocols`        | The list of enabled SSL/TLS protocols                                               | This option is commented out by default.  |
| `tls_exclude_cipher_suites`    | The list of disabled SSL/TLS cipher suites                                          | This option is commented out by default.  |
| `tls_include_cipher_suites`    | The list of enabled SSL/TLS cipher suites                                           | This option is commented out by default.  |

### /etc/voms-admin/voms-admin-server.logback <a name="admin_server_logback"></a>


This is logback configuration file, which controls the logging to the following files:

- `/var/log/voms-admin/server.log` (server messages)
- `/var/log/voms-admin/server-authn.log` (authentication-related messages)

For more information about logback configuration syntax, check the [logback documentation][logback-doc].

To change the verbosity of the authentication-related messages, for instance to get more
information about certificate-related issues, change the level for the `CANLListener` logger
from `INFO` to `DEBUG` as follows:

```xml
<configuration>
	...
	<logger name="org.italiangrid.utils.https.impl.canl.CANLListener" level="DEBUG" additivity="false">
	       <appender-ref ref="AUTHN" />
	</logger>
	<root level="INFO">
	       <appender-ref ref="FILE" />
	</root>	
</configuration>
```

## VO configuration <a name="vo_configuration"></a>


VOMS Admin configuration files can be found in `/etc/voms-admin/VO_NAME` for a given VO.

The following files control the configuration of a given VO:

- `service.properties`: the main VO configuration file
- `database.properties` : contains credentials and settings for accessing the database
- `logback.xml` : the VO logging configuration
- `vo-aup.txt` : the text of the default VO AUP 
- `vomses`: this file contains the vomses configuration displayed by the VOMS Admin webapp configuration page
- `lsc` : this file contains the lsc configuration displayed by the VOMS Admin webapp configuration page

All the options described below can be set using the `voms-configure` script.

### /etc/voms-admin/<span class="vo-highlight">vo</span>/service.properties <a name="service_props"></a>


This is a Java properties file.

#### Base service options <a name="va_service_props"></a>


| Property | Description | Default value |
|:---------|:------------|:--------------|
| `voms.hostname` | The hostname that should be used for requests and notifications | The output of `hostname -f` |
| `voms.registration.enabled` | Should the registration service be enabled? | True |
| `voms.readonly` | Is this a read-only VOMS instance | False |
| `voms.skip_ca_check` | Skip checks on certificate issuer (i.e. authenticate users considering only the certificate subject) | False |

#### Notification settings <a name="va_notification_props"></a>


| Property | Description | Default value |
|:---------|:------------|:--------------|
| `voms.notification.disable` | Disables the notification service. | False |
| `voms.notification.email-address` | The email address that will be used as the sender for VOMS Admin notification messages | N/A |
| `voms.notification.smtp-server` | The SMTP server used to dispatch notifications | N/A |
| `voms.notification.username` | The user used to authenticate to the STMP server | N/A |
| `voms.notification.password` | The password used to authenticate to the SMTP server | N/A |
| `voms.notification.use_tls` | Whether TLS should be used when contacting the SMTP server | False |

#### Membership validation settings  <a name="va_membership_validation_props"></a>


| Property | Description | Default value |
|:---------|:------------|:--------------|
| `voms.task.membership_check.period ` | How often (in seconds) the membership background thread should run | 600 |
| `voms.membership.default_lifetime` | Default VO membership lifetime duration (in months). This setting is used to compute the default membership expiration date for newly created users | 12 |
| `voms.membership.expiration_warning_period` | Warning period duration (in days). VOMS Admin will notify of users about to expire in the next number of days expressed by this option | 30 |
| `voms.membership.disable_expiration_warning` | Disables periodic membership expiration warning notifications | False |
| `voms.membership.expiration_grace_period` | Membership expiration grace period (in days). During the grace period the user will be maintained active even if its membership has expired. Note that this option has no effect if the `voms.preserve_expired_members` is set to True | 7 |
| `voms.membership.notification_resend_period` | Time (in days) that should pass between consecutive warning expiration messages sent to VO administrators to inform about expired and expiring VO members.| 1 |
| `voms.preserve_expired_members` | When this option value is true, expired users are NOT suspended. | False |
| `voms.disable_membership_end_time` | This flag disables the membership end time checks completely. Turn this setting to true in case you want that user membership lifetime is linked only to the AUP acceptance period. | False |

#### Registration service options <a name="va_registration_props"></a>


| Property                                                     | Description                                                                                                                                                                                                                                                   | Default value   |
| :---------                                                   | :------------                                                                                                                                                                                                                                                 | :-------------- |
| `voms.request.vo_membership.enable_attribute_requests`       | Enables the attribute request at registration time. Setting this option to true will allow users to request membership in groups also during their first registration at the VO. The VO manager will be given the chance to approve every membership request. | True            |
| `voms.request.vo_membership.require_group_manager_selection` | Require group manager selection at registration time, when GM are enabled.                                                                                                                                                                                    | True            |
| `voms.request.vo_membership.lifetime`                        | Time (in seconds) that unconfirmed membership requests are kept inside the voms database.                                                                                                                                                                     | 604800          |
| `voms.request.vo_membership.warn_when_expired`               | Should voms-admin send a warning email to the user when his/her unconfirmed request is removed from the database?                                                                                                                                             | True            |
| `voms.request.group_manager_role`                            | Sets a custom name for the group manager role.                                                                                                                                                                                                                | Group-Manager   |

#### AUP options <a name="va_aup_props"></a>


| Property | Description | Default value |
|:---------|:------------|:--------------|
| `voms.aup.initial_url` | The URL of the AUP configured by default | `file:/etc/voms-admin/<VO_NAME>/vo-aup.txt` |
| `voms.aup.sign_aup_task_lifetime` | The lifetime of Sign AUP task assigned to users. This is a grace period, in days, given to users to sign the AUP after the signature expiration. | 15 |
| `voms.aup.sign_aup_task_reminders` | Comma separated list of values that represent the days before the AUP grace period expiration when reminders should be sent to users that have a pending Sign AUP request | 7,3,1  |

#### SAML Attribute authority options  <a name="va_saml_props"></a>


| Property | Description | Default value |
|:---------|:------------|:--------------|
| `voms.aa.activate_saml_endpoint` | Should the VOMS SAML service be enabled? | False |
| `voms.saml.max_assertion_lifetime` | The lifetime of issued SAML assertion (in seconds) | 86400 |
| `voms.aa.compulsory_group_membership` | Set this to false to have a standard SAML AA behaviour. | True |

#### Other options <a name="va_other_props"></a>

| Property | Description | Default value |
|:---------|:------------|:--------------|
| `voms.csrf.log_only` | CSRF guard. When true, dubious requests are not blocked but logged. | False |
| `voms.mkgridmap.translate_dn_email_format` | Should voms-admin generate gridmapfiles that encode the email part of the DN using the "emailAddress" format in addition to the "Email=" format used by default? | False |

### /etc/voms-admin/<span class="vo-highlight">vo</span>/database.properties <a name="database_props"></a>


Look at the [Hibernate documentation][hibernate-doc] for more detailed information about these properties.

| Property | Description | Default value |
|:---------|:------------|:--------------|
|`hibernate.connection.driver_class` |  The Hibernate database driver | Depends on the database backend. Don't mess with this value unless you know exactly what you are doing |
|`hibernate.connection.url` | The database backend url | Depends on the database backend. Don't mess with this value unless you know exactly what you are doing |
|`hibernate.dialect` | The Hibernate database dialect | Depends on the database backend. Don't mess with this value unless you know exactly what you are doing |
|`hibernate.connection.username` | The username used to authenticate to the database | N/A |
|`hibernate.connection.password` | The password used to authenticate to the database | N/A |

#### Database connection pool settings

Look at the [c3p0 documentation][c3p0-doc] to know about connection pool tuning.

| Property | Description | Default value |
|:---------|:------------|:--------------|
|`hibernate.c3p0.acquire_increment` | Determines how many connections at a time c3p0 will try to acquire when the pool is exhausted. | 1 |
|`hibernate.c3p0.idle_test_period` | If this is a number greater than 0, c3p0 will test all idle, pooled but unchecked-out connections, every this number of seconds. | 0 |
|`hibernate.c3p0.min_size` | Minimum number of Connections a pool will maintain at any given time. | 1 |
|`hibernate.c3p0.max_size` | Maximum number of Connections a pool will maintain at any given time. | 100 |
|`hibernate.c3p0.max_statements` | Number of cached prepared statements (across all connections). See [c3p0 doc](http://www.mchange.com/projects/c3p0/index.html#maxStatements). | 50 |
|`hibernate.c3p0.timeout` | Seconds a Connection can remain pooled but unused before being discarded. Zero means idle connections never expire. | 60 |

### /etc/voms-admin/<span class="vo-highlight">vo</span>/logback.xml <a name="vo_logback"></a>


This is logback configuration file. For more information about logback configuration syntax, check the [logback documentation][logback-doc].

By default all log messages for a VO will go to `/var/log/voms-admin/voms-admin-VO_NAME.log`.

This file is well commented, and explains how to change log levels for separate parts of the VOMS Admin service.

An example configuration file is listed below:

```xml
<configuration>
    <!--
        This logger controls the MAIN voms admin log messages. Set the level to DEBUG 
        for maximum detail.  
     -->
    <logger name="org.glite.security.voms.admin" level="INFO" />
    <!--
         This logger controls the main validation service VOMS Admin log messages.
         Set the level to DEBUG for maximum detail.
    -->
    <logger name="org.glite.security.voms.admin.core.validation" level="DEBUG"/>
    
    <!-- 
        This logger controls the log messages produced when exceptions are raised by a call to the voms admin
        web services. Set the level to DEBUG for maximum detail.  
     -->
    <logger
        name="org.glite.security.voms.admin.service.ServiceExceptionHelper"
        level="DEBUG" />
    
    <!-- 
        The loggers below control the amount of logging produced by the main frameworks used by voms admin. Normally
        you shouldn't change the defaults listed here.
     -->
    <logger name="org.opensaml" level="ERROR" />
    
    <!-- 
        Set the level to INFO (or DEBUG) for the hibernate logging if you want to have more detailed log messages regarding
        the persistence management in voms-admin.
     -->
    <logger name="org.hibernate" level="ERROR" />
    
    <logger name="org.apache.struts2" level="WARN" />
    <logger name="com.opensymphony.xwork2" level="WARN" />
    <logger name="com.opensymphony.xwork2.config.providers.XmlConfigurationProvider" level="ERROR" />
    
    <!-- NORMALLY YOU SHOULD NOT EDIT BELOW THIS POINT  -->
    <appender name="FILE"
        class="ch.qos.logback.core.rolling.RollingFileAppender">
        <File>/var/log/voms-admin/voms-admin-${voms.vo.name}.log</File>
        <rollingPolicy
            class="ch.qos.logback.core.rolling.TimeBasedRollingPolicy">
            <FileNamePattern>/var/log/voms-admin/voms-admin-${voms.vo.name}-%d{yyyy-MM-dd}.log</FileNamePattern>
        </rollingPolicy>

        <encoder>
            <pattern>%date{yyyy-MM-dd HH:mm:ss.SSS'Z',UTC} - %level [%logger{0}] - %msg%n</pattern>
        </encoder>
    </appender>    
    
    <root level="WARN">
        <appender-ref ref="FILE" />
    </root>
    
</configuration>
```
### CERN HR plugin configuration <a name="cern_hr"></a>

<div class="alert alert-error">
These instructions are only valid for the CERN VOMS deployment.
</div>

The VOMS HR plugin provides integration with the CERN Human Resource database
(aka OrgDB). 

When the CERN HR integration is active:

- registration requests are validated so that only applicants present in the
  experiment in the HR database can apply for VO membership.
- VO membership expiration time is linked to the HR membership expiration.

A periodic background task keeps the information in VOMS in sync with the
information in the HR.

The CERN HR db plugin replaces the former OrgbDB plugin. This plugin integrated
with a REST API services in front of the HR database, while the OrgDB plugin
connected directly to the CERN Oracle database.

#### Enabling the HR plugin <a name="cern_hr_enable"></a>

The plugin configuration is currently **not** supported by `voms-configure`.

Assuming the VO for which the OrgDB plugin must be enabled is already
configured, you will need to do the following changes to the configuration:

- Edit the `/etc/voms-admin/<vo-name>/service.properties` file for the VO to
  enable the plugin.
- Create the file `/etc/voms-admin/<vo-name>/hr.properties` that will hold the 
  plugin configuration.

#### Changes to the service.properties file

Add the following lines at the bottom of the `service.properties` file:

	## External validation plugin options
	voms.external-validators = orgdb
	voms.ext.orgdb.configClass = org.glite.security.voms.admin.integration.cern.HrDbConfigurator

#### The hr.properties configuration file

The `hr.properties` defines the configuration for the HR plugin. 

```
# The experiment name.
experiment=atlas

# How frequently the check is run (in seconds). Default: 43200
membership_check.period=43200

# Should the membership check be enabled. Default: true
membership_check.enabled=true/false

# At what time should the first hr sync be triggered ? Default: 23
membership_check.start_hour=23

# When true triggers an hr sync 5 mins after startup (I'd set this to
# false in production) Default: true
membership_check.run_at_startup=true/false
```

So if in production you want the sync to run every 12h starting at 2 in the
morning, the right configuration is:

```
membership_check.enabled=true
membership_check.start_hour=2
membership_check.run_at_startup=false
```

### Other configuration utilities <a name="config_utils"></a>

#### voms-mysql-util

The `voms-mysql-util` command is used for the creation or removal of the
database that will host the VOMS services tables on a MySQL database backend.
This command does not create the VOMS tables. This is done by the
`voms-db-util` command, which is described below. As `voms-mysql-util` is
invoked internally by `voms-configure` normally system administrators do not
use it, but it can sometimes be of help.

The general invocation is

```bash
voms-mysql-util COMMAND OPTIONS
```

Available options are:

* `create_db`  creates a MySQL database and grants read and write access
* `drop_db`  drops a MySQL database
* `grant_rw_access`  grants read and write access to a user
* `grant_ro_access`  grants read-only access to a user

The options are described in the following table

| Option | Description | Default value |
|:--------:|:-----------:|:-------------:|
| `--dbhost HOST` | Uses HOST when connecting to MySQL. | localhost |
| `--dbport PORT` | Uses PORT when connecting to MySQL. | 3306 |
| `--mysql-command CMD` | Uses CMD ad mysql command. | mysql |
| `--dbauser USER` | Uses USER when connecting to MySQL. USER must have the rights to create database and grant access to them. | root |
| `--dbapwd PWD` | Uses PWD when connecting to MySQL. This is the password of the user specified using the --dbauser option.|
| `--dbapwdfile FILE` | Reads the password to connect to the database from FILE. |
| `--dbusername USER` | Sets the database username to USER. |
| `--dbpassword PWD` | Sets the database password to PWD |
| `--vomshost HOST` | Sets the HOST where VOMS is running. This is the host from which MySQL will receive connections for the database. |
| `--dbname DBNAME` | Sets the VOMS database name to DBNAME. |

#### voms-db-util

The `voms-db-util` command is used to manage the deployment and upgrade of the VOMS database tables, and to add/remove administrators without requiring VOMS Admin VOs to be active. As `voms-db-util` is invoked internally by `voms-configure` normally system administrators do not use it, but it can sometimes be of help.

The general invocation is

```bash
voms-db-util COMMAND [OPTIONS]
```

The commands for installing or removing the database are

* `check-connectivity` check whether the database can be contacted
* `deploy` deploys the database for a given VO
* `undeploy` undeploys the database for a given VO
* `upgrade` upgrades the database for a given VO

The commands for adding or removing administrators are

* `add-admin` creates an administrator with full privileges for a given VO
* `remove-admin` removes an administrator from a given VO
* `grant-read-only-access`  creates ACLs so that VO structure is readable for any authenticated user

The options are described in the following table

| Option | Description |
|:--------:|:-----------:|
| `--vo` | The VO for which database operations are performed |
| `--dn` | The DN of the administrator certificate |
| `--ca` | The DN of the CA that issued the administrator certificate |
| `--email` | The EMAIL address of the administrator |
| `--cert` | The x.509 CERTIFICATE of the administrator being created |
| `--ignore-cert-email` | Ignores the email address in the certificate passed in with the --cert option |

#### voms-vo-ctl

The `voms-vo-ctl` command, introduced with the CENTOS7 release, is used to
manage the deployment of VOs for the voms-admin service. 

```bash
# voms-vo-ctl --help
Usage: /usr/sbin/voms-vo-ctl {list|deploy|undeploy}
```

### Information system <a name="info-system">&nbsp;</a>

#### BDII <a name="bdii">&nbsp;</a>

##### Configure the info providers

The script `voms-config-info-providers` configures the providers for the resource bdii. Run

```bash
voms-config-info-providers -s SITENAME -e
```

giving the site name (which in the past went into the sitedef configuration file). If not deploying the administration service, skip the -e option.

Start the bdii service and check services are published. The query

```bash
ldapsearch -x -h localhost -p 2170 -b 'GLUE2GroupID=resource,o=glue' objectCLass=GLUE2Service
```

should return a service for each virtual organization.

#### EMIR <a name="emir">&nbsp;</a>

You can use [EMIR-SERP](https://twiki.cern.ch/twiki/bin/view/EMI/SERP) to publish VOMS information to EMIR. EMIR-SERP uses the information already available in the resource bdii and publish it to an EMIR DSR endpoint. You have to know the EMIR endpoint to do this, in the following example the EMI testbed EMIR
endpoint is used.

Install emir-serp

```bash
yum install emir-serp
```

and edit the configuration file `/etc/emi/emir-serp/emir-serp.ini`, providing the url for the EMIR DSR and the url for the resource bdii

```bash
...
url = http://emitbdsr1.cern.ch:9126
...
[servicesFromResourceBDII]
resource_bdii_url = ldap://localhost:2170/GLUE2GroupID=resource,o=glue
...
```

See the configuration file documentation for other options. You for sure will want to change the validity (the time EMIR DSR is told to consider the information valid) and period (the interval at which emir-serp will check for change in the bdii and refresh the publishing) attributes

```bash
# Period of registration/update messages
# Mandatory configuration parameter
# Value is given in hours
period = 1

# Time of registration entry validity
# Mandatory configuration parameter
# Value is given in hours
validity = 1
```

Start emir-serp with

```bash
service emir-serp start
```

and check your EMIR deployment to make sure the endpoints are published. You can spot problems increasing the verbosity of the emir-serp logging by editing the configuration file 

```bash
verbosity = debug
```

[c3p0-doc]: http://www.mchange.com/projects/c3p0/index.html#hibernate-specific
[hibernate-doc]: http://docs.jboss.org/hibernate/orm/3.3/reference/en/html/session-configuration.html#configuration-hibernatejdbc
[logback-doc]: http://logback.qos.ch/manual/configuration.html
