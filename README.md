# VOMS

The Virtual Organization Membership Service (VOMS) is an attribute authority
which serves as central repository for VO user authorization information,
providing support for sorting users into group hierarchies, keeping track of
their roles and other attributes in order to issue trusted attribute
certificates and SAML assertions used in the Grid environment for authorization
purposes.

# For system administrators

## Quickstart

This quickstart guide covers the MySQL installation of VOMS.

* Install the EMI 2 release package.
* Install the emi-voms-mysql metapackage.
* Install the xml-commons-apis package to avoid useless warnings when running Tomcat.
* Set a sensible password for the MySQL root user, as explained in the instructions below.
* Configure the VOMS service with YAIM as explained in this section.

## Prerequisites and recommendations

### Hardware

* CPU: No specific requirements
* Memory: 2GB if serving <= 10 VOs, more otherwise
* Disk: 10GB free space (besides OS and EMI packages)

### Operating system

* NTP Time synchronization: required.
* Host certificates: required
* Networking
	* Open ports : see service reference card

### Installed software

Besides the usual OS and EMI release packages, you will need the `oracle-instantclient-basic` package, version 10.2.0.4, installed on the system (in case of an Oracle-based installation).

All the other dependencies are resolved by the installation of the VOMS metapackages, i.e.:

* `emi-voms-mysql`, in case of a MySQL installation,
* `emi-voms-oracle`, in case of an Oracle installation.

## Recommended deployment scenarios

A single-node installation, with the hardware recommendations given above should serve well most scenarios. It is not recommended to deploy a large number of VOs (> 20) on a single installation. This is due to an architectural limitation of VOMS (i.e., independent web applications and service for each VO) that will be solved in a future VOMS release.

## Installation

### Repositories

Follow the general EMI 1 or 2 installation instructions. VOMS requires that the OS and EPEL repositories are active and correctly configured on the target machine. If oracle is used, a repository where Oracle packages are available should also be provided. Otherwise Oracle packages need to be installed manually.

### Clean installation

In case you plan to install the `emi-voms-oracle` metapackage, download and install the Oracle instant client basic libraries (v. 10.2.0.4-1) on your system:
```bash
yum localinstall oracle-instantclient-basic-10.2.0.4-1.x86_64.rpm
```

Install the `emi-voms-mysql` metapackage or `emi-voms-oracle` depending on the database backend you are using (mysql or Oracle):
```bash
yum install emi-voms-mysql or yum install emi-voms-oracle
```

Manually install `xml-commons-apis` libraries (after having installed the right metapackage for your installation), as the ones provided by the default OS JREs cause warnings when starting/stopping tomcat:
```bash
yum install xml-commons-apis
```

### Upgrade from gLite 3.2

#### Install and configure a SL5 or SL6 X86_64 EPEL machine

In order to install the EMI VOMS metapackage you will need a clean SL5 or SL6 X86_64 machine with the EPEL repository configured and the emi release package correctly installed.

SL5, as configured by gLite 3.2, is not suitable for installing the EMI VOMS since gLite uses the DAG repository, which is alternative and incompatible with EPEL.

Once you have a clean machine configured, install the `emi-voms-mysql` metapackage, without **launching yaim configuration**.

#### VOMS database dump and YAIM configuration

On your existing gLite 3.2 VOMS node dump the VOMS database for all the VOs issuing the following command:

```bash
mysqldump -uroot -p<MYSQL_ROOT_PASSWORD> --all-databases --flush-privileges > voms_database_dump.sql
```

You will then copy the dump file on the new EMI VOMS node.

Remember to save your YAIM configuration (in most cases, `site-info.def` and `services/glite-voms` in your `siteinfo` directory) and copy it on the new EMI VOMS node.

#### Restoring the VOMS database on the EMI node

You should now have the mysql daemon installed in your EMI machine (it was installed as a dependency of the `emi-voms-mysql` metapackage). Follow the instructions in this section to properly configure the mysql root account.

Once the root account is configured and working (check that you can login issuing the command `mysql -uroot -p<MYSQL_ROOT_PASSWORD>`), you can restore the VOMS database issuing the following command:

```bash
mysql -uroot -p<PASSWORD> < voms_database_dump.sql
```

#### Configuring VOMS on the EMI node

The gLite 3.2 YAIM configuration should work in your EMI installation. Just check that no gLite-specific paths are referenced in your configuration and possibly integrate it with the new options provided by EMI VOMS.

When upgrading an Oracle installation follow these instructions before configuring the VOMS services with YAIM.

In order to configure VOMS, place the YAIM configuration files in your favorite directory and launch the following command:

```bash
/opt/glite/yaim/bin/yaim -c -s site-info.def -n VOMS
```

#### Upgrading a VOMS Oracle installation

On Oracle, a database schema upgrade is required when upgrading from gLite 3.2 or EMI 1. The schema upgrade should be performed before running the YAIM configuration following this procedure:

Backup the contents of the VOMS databases uses the appropriate tools as described in Oracle documentation.

Run voms-admin-configure upgrade

Reconfigure the services with YAIM (as described in the previous section)

####  Known issues for the gLite 3.2 to EMI upgrade

The AUP may not be shown correctly after upgrade to EMI. After upgrading a gLite 3.2 VOMS Admin the URL pointing to the default AUP text (/var/glite/etc/voms-admin//vo-aup.txt) is not upgraded to the new location (/etc/voms-admin//vo-aup.txt). This issue lead to an empty AUP shown to the users for the upgraded VOMS. To solve this issue, change the AUP url from the VOMS admin web interface by pointing your browser to: https://<voms-hostname>:8443/voms/<vo>/aup/load.action
The default URL for the new aup is:
file:/etc/voms-admin/<vo>/vo-aup.txt

### Upgrade from EMI 1 VOMS

#### Upgrading an SL5 EMI 1 installation

* Install the emi-release package for EMI 2.
* Update packages via yum update.
* Restart the services

When upgrading an Oracle installation, follow this procedure:

* Install the emi-release package for EMI 2.
* Update packages via yum update.
* Stop the services (voms and tomcat)
* Backup the contents of the VOMS databases uses the appropriate tools as described in Oracle documentation.
* Run voms-admin-configure upgrade
* Restart the services

## Configuration

### Configuring the database backend

#### MySQL configuration

Make sure that the MySQL administrator password that you specify in the YAIM VOMS configuration files matches the password that is set for the root MySQL account. Yaim configuration script does not set it for you. If you want to set a MySQL administrator password:

Check that mySQL is running; if it is not, launch it using `service mysqld start`. Then issue the following commands as root in order to set a password for the mysql root account
```bash
/usr/bin/mysqladmin -u root password <adminPassword>
/usr/bin/mysqladmin -u root -h <hostname> password <adminPassword>;
```

### Oracle configuration

Create the necessary users and databases in Oracle. Please see the Oracle manuals for details.

In order to properly configure the library load path for the VOMS oracle backend, create a file named `oracle-x86_64.conf` in the `/etc/ld.so.conf.d` directory, with the following content:
```bash
/usr/lib/oracle/10.2.0.4/client64/lib
```

In case you use a different version of the the instantclient libraries (not recommended) , adjust the above accordingly.

### Configuring the VOMS server with YAIM

Check the VOMS YAIM configuration guide.


## Service operation

The YAIM configuration step is enough to have the VOMS core and admin services up and running. To start and stop the VOMS core service use:

```bash
service voms start
```

To start and stop VOMS admin, use the tomcat scripts (that's for SL5, would be `tomcat6` on SL6)

```bash
service tomcat5 start
```bash

If you want to restart individual VOMS admin VO web applications, you can use:

```bash
service voms-admin start/stop <vo>
```

Use the above commands only in exceptional cases, and to deal with potential issues that affect only individual VOs. The recommended way to start and stop VOMS admin is by using the tomcat startup scripts.

### 1.5.2 Migration

In order to migrate VOMS to a different machine, you first need to move the configurations files. Archive the contents of the YAIM configuration directory and move this archive to the new installation. In case YAIM is not used, you will need to archive and move the `/etc/voms/*` and `/etc/voms-admin/*` directories if on a EMI-1 installation, or `$GLITE_LOCATION/etc/voms/*` and `$GLITE_LOCATION_VAR/etc/voms-admin/*` on a gLite 3.2 installation.

Then you need to migrate the database content. This holds only if VOMS was configured to access a local database instance. if a remote database is used for VOMS only the configuration will need to be migrated to the new installation.

In order to dump the contents of the VOMS database issue the following command on the original VOMS installation machine:

```bash
mysqldump -uroot -p<MYSQL_ROOT_PASSWORD> --all-databases --flush-privileges > voms_database_dump.sql
```

To restore the database contents on the new VOMS installation machine, ensure that the mysql-server is installed and running and the password for the MySQL root account is properly configured (follow the instructions in this section to configure the root account password). The database content can then be restored using the following command
```bash
mysql -uroot -p<PASSWORD> < voms_database_dump.sql
```







## Support

Having problem with VOMS? Submit a ticket in
[GGUS](https://ggus.eu/pages/ticket.php) targeted at the VOMS EMI support unit.

## License

Licensed under the Apache License, Version 2.0 (the "License"); you may not use
this project except in compliance with the License. You may obtain a copy of
the License at http://www.apache.org/licenses/LICENSE-2.0.

Unless required by applicable law or agreed to in writing, software distributed
under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
CONDITIONS OF ANY KIND, either express or implied. See the License for the
specific language governing permissions and limitations under the License.
