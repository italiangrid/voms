---
layout: default
version: 3.0.14
title: VOMS System Administrator Guide - Operations
---

# VOMS Services operations

{% include sysadmin-guide-version.liquid %}


## CENTOS 7

The commands used to start and stop VOs in CENTOS 7 changed with the move to systemd.

To enable VOs in VOMS admin, you must use the `voms-vo-ctl` utility. For example,
the following command

```bash
voms-vo-ctl deploy atlas
```


To start and stop all VOs on the machine, use the following commands:

```bash
systemctl start voms@'*'
systemctl start voms-admin
```

To start or stop a specific VO, use the following commands:

```bash
service voms start <vo>
service voms-admin start <vo> 
```

### Log files locations

|Service| Directory| Filename |
|:------|:---------|:---------|
| VOMS core | `/var/log/voms` | voms.VO_NAME |
| VOMS admin | `/var/log/voms-admin` | voms-admin-VO_NAME.log |
| VOMS admin | `/var/log/voms-admin` | server.log |

### Logging verbosity configuration

#### VOMS core

The VOMS core service logging verbosity is set with the `--loglevel`
option in the:
```
/etc/voms/VO_NAME/voms.conf
```

Log levels are numeric values which have the meaning defined in the following table:

| Value | Level name | Meaning |
|:---|:----------|:------------|
| 1 | LEV_NONE | Do not log |
| 2 | LEV_ERROR | Log only error messages |
| 3 | LEV_WARN | Log warn error messages and above |
| 4 | LEV_INFO | Log info messages and above |
| 5 | LEV_DEBUG | Log debug messages and above |

&nbsp;

The `--logtype` flag controls which type of information is logged by the voms server.
The default value for this option is `7` and should be left configured so.

#### VOMS admin

The VOMS admin service uses logback for logging configuration. 

The container level logging configuration is maintained in the file:

```
/etc/voms-admin/voms-admin-server.logback
```

while for a given VO is maintained in the file:

```
/etc/voms-admin/VO_NAME/logback.xml
```

Instructions for configuring the logging can be found directly in the configuration files.

##### voms-db-util logging

To change the verbosity of the voms-db-util command, refer to the 
following logback configuration file:
```
/var/lib/voms-admin/tools/logback.xml
```

## Troubleshooting <a name="Troubleshooting">&nbsp;</a>

See the [known issues page]({{ site.baseurl }}/documentation/known-issues)

[voms-conf-ref]: {{site.baseurl}}/documentation/sysadmin-guide/{{page.version}}/configuration.html
[umd]: http://repository.egi.eu/category/umd_releases/distribution/umd-3/
