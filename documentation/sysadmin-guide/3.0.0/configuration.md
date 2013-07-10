---
layout: default
title: VOMS services configuration 
---

# VOMS configuration

### /etc/sysconfig/voms
This file contains variables needed by startup scripts to properly execute the VOMS service

| Property | Description | Default value |
|:--------:|:-----------:|:-------------:|
| `VOMS_USER` | The user under which the VOMS process will run | `voms` |
| `TNS_ADMIN` | Default oracle tnsnames.ora location | `/etc/voms` |


## Service configuration 

The VOMS server configuration for a VO can be found in `/etc/voms/VO_NAME` and is composed of two files:

- `voms.conf` containing the server configuration
- `voms.pass` containing the password used to access the database

### /etc/voms/<span class="vo-highlight">vo</span>/voms.conf

The server configuration file is a text file containing a series of command line options that is parsed by the VOMS
daemon at startup time. Check the VOMS man page for more information.

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

### /etc/voms/<span class="vo-highlight">vo</span>/voms.pass

This is a text containing only the password used by the VOMS server to connect to the database.

# VOMS Admin configuration 

### /etc/sysconfig/voms-admin

This file contains variables needed by startup scripts to properly execute the VOMS Admin services

| Property | Description | Default value |
|:---------|:------------|:--------------|
| `PREFIX` | The prefix for the VOMS Admin installation | `/` |
| `CONF_DIR` | The path where VOMS Admin configuration files are located | `/etc/voms-admin` |
| `VOMS_USER` |  The user under which the VOMS Admin process will run | `voms` |
| `ORACLE_LIBRARY_PATH` | The path to oracle native libraries | `/usr/lib64/oracle/11.2.0.3.0/client/lib64` |
| `TNS_ADMIN` | Default oracle tnsnames.ora location | `/etc/voms` |


## Container configuration

VOMS Admin container configuration can be found in the `/etc/voms-admin` directory.
The container configuration consists of two files:

- `voms-admin-server.properties`
- `voms-admin-server.logback`

### /etc/voms-admin/voms-admin-server.properties

This is a standard Java properties file. 

| Property | Description | Default value |
|:---------|:------------|:--------------|
| `host` | The hostname where service is accepting requests | The output of `hostname -f` |
| `port` | The port where the service will be accepting requests | 8443 |
| `cert` | The service PEM encoded X.509 certificate | `/etc/grid-security/vomscert.pem` |
| `key`  | The service private key | `/etc/grid-security/vomskey.pem` |
| `trust_anchors.dir` | The trust anchors directory, i.e. where CA certificates and CRLs will be looked for | `/etc/grid-security/certificates` |
| `trust_anchors.refresh_period` | How ofter trust anchors are refreshed from the trust anchors dir (in seconds) | 3600 (i.e. every hour) |
| `max_connections` | Maximum number of concurrent connections accepted by the service | 50 |
| `max_request_queue_size` | Maximum number of client requests queued | 200 |

### /etc/voms-admin/voms-admin-server.logback

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

## VO configuration

VOMS Admin configuration files can be found in `/etc/voms-admin/VO_NAME` for a given VO.

The following files control the configuration of a given VO:

- `service.properties`: the main VO configuration file
- `database.properties` : contains credentials and settings for accessing the database
- `logback.xml` : the VO logging configuration
- `vo-aup.txt` : the text of the default VO AUP 
- `vomses`: this file contains the vomses configuration displayed by the VOMS Admin webapp configuration page
- `lsc` : this file contains the lsc configuration displayed by the VOMS Admin webapp configuration page


All the options described below can be set using the `voms-configure` script.

### /etc/voms-admin/<span class="vo-highlight">vo</span>/service.properties

This is a Java properties file.

#### Base service options

| Property | Description | Default value |
|:---------|:------------|:--------------|
| `voms.hostname` | The hostname that should be used for requests and notifications | The output of `hostname -f` |
| `voms.registration.enabled` | Should the registration service be enabled? | True |
| `voms.readonly` | Is this a read-only VOMS instance | False |

#### Notification settings

| Property | Description | Default value |
|:---------|:------------|:--------------|
| `voms.notification.disable` | Disables the notification service. | False |
| `voms.notification.email-address` | The email address that will be used as the sender for VOMS Admin notification messages | N/A |
| `voms.notification.smtp-server` | The SMTP server used to dispatch notifications | N/A |
| `voms.notification.username` | The user used to authenticate to the STMP server | N/A |
| `voms.notification.password` | The password used to authenticate to the SMTP server | N/A |
| `voms.notification.use_tls` | Whether TLS should be used when contacting the SMTP server | False |

#### Membership validation settings

| Property | Description | Default value |
|:---------|:------------|:--------------|
| `voms.task.membership_check.period ` | How often (in seconds) the membership background thread should run | 600 |
| `voms.membership.default_lifetime` | Default VO membership lifetime duration (in months). This setting is used to compute the default membership expiration date for newly created users | 12 |
| `voms.membership.expiration_warning_period` | Warning period duration (in days). VOMS Admin will notify of users about to expire in the next number of days expressed by this option | 30 |
| `voms.membership.expiration_grace_period` | Membership expiration grace period (in days). During the grace period the user will be maintained active even if its membership has expired. Note that this option has no effect if the `voms.preserve_expired_members` is set to True | 7 |
| `voms.membership.notification_resend_period` | Time (in days) that should pass between consecutive warning expiration messages sent to VO administrators to inform about expired and expiring VO members.| 1 |
| `voms.preserve_expired_members` | When this option value is true, expired users are NOT suspended. | False |
| `voms.disable_membership_end_time` | This flag disables the membership end time checks completely. Turn this setting to true in case you want that user membership lifetime is linked only to the AUP acceptance period. | False |

#### Registration service options

| Property | Description | Default value |
|:---------|:------------|:--------------|
| `voms.request.vo_membership.enable_attribute_requests` | Enables the attribute request at registration time. Setting this option to true will allow users to request membership in groups also during their first registration at the VO. The VO manager will be given the chance to approve every membership request. | True |
| `voms.request.vo_membership.lifetime` | Time (in seconds) that unconfirmed membership requests are kept inside the voms database. | 604800 |
| `voms.request.vo_membership.warn_when_expired` | Should voms-admin send a warning email to the user when his/her unconfirmed request is removed from the database? | True |
| `voms.mkgridmap.translate_dn_email_format` | Should voms-admin generate gridmapfiles that encode the email part of the DN using the "emailAddress" format in addition to the "Email=" format used by default? | False |

#### AUP options

| Property | Description | Default value |
|:---------|:------------|:--------------|
| `voms.aup.initial_url` | The URL of the AUP configured by default | `file:/etc/voms-admin/<VO_NAME>/vo-aup.txt` |
| `voms.aup.sign_aup_task_lifetime` | The time (in days) given to users to sign the AUP, after being notified, before being suspended. | 15 |

#### SAML Attribute authority options

| Property | Description | Default value |
|:---------|:------------|:--------------|
| `voms.aa.activate_saml_endpoint` | Should the VOMS SAML service be enabled? | False |
| `voms.saml.max_assertion_lifetime` | The lifetime of issued SAML assertion (in seconds) | 86400 |
| `voms.aa.compulsory_group_membership` | Set this to false to have a standard SAML AA behaviour. | True |

#### Other options
| Property | Description | Default value |
|:---------|:------------|:--------------|
| `voms.csrf.log_only` | CSRF guard. When true, dubious requests are not blocked but logged. | False |

### /etc/voms-admin/<span class="vo-highlight">vo</span>/database.properties

Look at the [Hibernate documentation][hibernate-doc] for more detailed information about these properties.

| Property | Description | Default value |
|:---------|:------------|:--------------|
|`hibernate.connection.driver_class` |  The Hibernate database driver | Depends on the database backend. Don't mess with this value unless you know exactly what you are doing |
|`hibernate.connection.url` | The database backend url | Depends on the database backend. Don't mess with this value unless you know exactly what you are doing |
|`hibernate.dialect` | The Hibernate database dialect | Depends on the database backend. Don't mess with this value unless you know exactly what you are doing |
|`hibernate.connection.username` | The username used to authenticate to the database | N/A |
|`hibernate.connection.password` | The password used to authenticate to the database | N/A |

#### Connection pool settings

Look at the [c3p0 documentation][c3p0-doc] to know about connection pool tuning. 

| Property | Description | Default value |
|:---------|:------------|:--------------|
|`hibernate.c3p0.acquire_increment` | Determines how many connections at a time c3p0 will try to acquire when the pool is exhausted. | 1 |
|`hibernate.c3p0.idle_test_period` | If this is a number greater than 0, c3p0 will test all idle, pooled but unchecked-out connections, every this number of seconds. | 0 |
|`hibernate.c3p0.min_size` | Minimum number of Connections a pool will maintain at any given time. | 1 |
|`hibernate.c3p0.max_size` | Maximum number of Connections a pool will maintain at any given time. | 100 |
|`hibernate.c3p0.max_statements` | Number of cached prepared statements (across all connections). See [c3p0 doc](http://www.mchange.com/projects/c3p0/index.html#maxStatements). | 50 |
|`hibernate.c3p0.timeout` | Seconds a Connection can remain pooled but unused before being discarded. Zero means idle connections never expire. | 60 |

### /etc/voms-admin/<span class="vo-highlight">vo</span>/logback.xml

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


[c3p0-doc]: http://www.mchange.com/projects/c3p0/index.html#hibernate-specific
[hibernate-doc]: http://docs.jboss.org/hibernate/orm/3.3/reference/en/html/session-configuration.html#configuration-hibernatejdbc
[logback-doc]: http://logback.qos.ch/manual/configuration.html
