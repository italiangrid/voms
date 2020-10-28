---
layout: default
version: 3.0.13
title: VOMS upgrade guide 
---

# VOMS upgrade installation instructions

{% include sysadmin-guide-version.liquid %}

### Upgrade preparation

It is always a good idea to dump the contents of the VOMS database. For MySQL-based installation follow
the instructions in the [database migration section](#Migration).

Also archive the configuration files for VOMS and VOMS-Admin, which live in the following directories:
```
/etc/voms
/etc/voms-admin
```
### UMD repository configuration <a name="Repository">&nbsp;</a>

Follow the [UMD installation instructions][umd] to install basic UMD
repositories.

If you want to install packages from the VOMS repository, follow the
instructions given [here]({{site.baseurl}}/releases.html).

### Upgrading to the latest VOMS release <a name="Upgrading">&nbsp;</a>

After having properly configured the repositories as explained in the previous section, just run:

```bash
yum update
```
to get the latest versions of the VOMS packages.

If the release notes indicate that a reconfiguration of the services is required, run `voms-configure` with the same parameters
that you used the first time you configured the VO. See the [Configuration section](#Configuration) for more information on how
to install and reconfigure the VOMS services.

If the release notes indicate that restarting the VOMS services is required, run

- Scientific Linux 6:

  ```bash
  service voms restart
  service voms-admin restart
  ```

- CENTOS 7

  ```bash
  systemctl restart voms@'*'
  systemctl restart voms-admin
  ```

#### <span class="label label-important">db upgrade</span> Upgrading the VOMS database <a name="db-upgrade">&nbsp;</a> 
If the release notes of the version that you are installing indicate that an
upgrade of the VOMS database is required, follow the procedure described below:

1. Stop the services.
2. Backup the contents of the VOMS database following the instructions in the [database migration section](#Migration).
3. Run the upgrade script for each configured vo as follows:

   ```bash
   voms-db-util upgrade --vo <vo_name>
   ```

4. Restart the services

### Configuring the VOMS Admin container <a name="ContainerConf">&nbsp;</a>

Since version 3.0.1 VOMS Admin does not depend anymore on Tomcat but uses an
embedded Jetty container for running the VO web applications. Please set the
host, port and ssl information by editing the

```
/etc/voms-admin/voms-admin-server.properties
```

before reconfiguring the VOs (as explained in the following sections) or start
the voms-admin server. See the [VOMS configuration reference][voms-conf-ref]
for a detailed reference of configuration parameters.

#### Configuring file limits for the VOMS Admin container

It is safe to configure the VOMS Admin container to have a reasonable limit for
the number of open files that can be opened by the voms-admin process (which
runs as user `voms`). The default file limit can be modified by editing the
`/etc/security/limits.conf` file:

```
voms          soft    nofile  63536
voms          hard    nofile  63536
```

#### Configuring memory for the VOMS Admin container <a name="voms-admin-mem-conf"></a>

The default Java VM memory configuration for the VOMS Admin container is
suitable for deployments which have at max 10 VOs configured, and is set in the
voms-admin init script:

```bash
VOMS_JAVA_OPTS="-Xms256m -Xmx512m -XX:MaxPermSize=512m"
```

In case your server will host more VOs, you should adapt the memory
configuration for the container accordingly. This can be done by setting the
`VOMS_JAVA_OPTS` variable in the `/etc/sysconfig/voms-admin` file. We recommend
to allocate roughly 50m of heap space and 75m of permanent space per VO. For
example, for 15 VOs, the memory should be configured as follows:

```bash
VOMS_JAVA_OPTS="-Xms375m -Xmx750m -XX:MaxPermSize=1125m"
```

### <span class="label label-info">reconfiguration</span> Reconfiguring the VOs <a name="reconf"></a>

Sometimes a VOMS Admin upgrade requires a reconfiguration.

The VOs can be reconfigured using the `voms-configure` configuration tool (YAIM
is no longer supported), or your favourite configuration management tool (e.g.,
puppet).

The `voms-configure` tool is the evolution of the `voms-admin-configure`
script, and provides access to most VOMS and VOMS-Admin service configuration
parameters. For more detailed information about the `voms-configure` tool, see
the [configuration section](#Configuration).

The following command shows a basic reconfiguration of the VO:

```bash
voms-configure install \
--vo <vo_name> \
--hostname <hostname> \
--dbname <dbname> \
--dbusername <dbusername> \
--dbpassword <dbpassword> \
--core-port 15000 \
--mail-from <mail-from> \
--smtp-host <smtp-host>
```

The above command will migrate the configuration to the latest supported
version.

<div class="alert alert-info">
  <i class="icon-eye-open"></i> Save the command you use to configure your VOs in a script for future reference. 
</div>

Once the configuration is over, you will need to upgrade the database as
explained in the [database upgrade section](#db-upgrade), i.e. running:

```bash
voms-configure upgrade --vo <vo_name>
```

for each configured VO and then restart the services with the following
commands:

- Scientific Linux 6:

  ```bash
  service voms restart
  service voms-admin restart
  ```

- CENTOS 7

  ```bash
  systemctl restart voms@'*'
  systemctl restart voms-admin
  ```

### Reconfiguring the information system

Follow the advice in the [Configuration reference
guide](configuration.html).
