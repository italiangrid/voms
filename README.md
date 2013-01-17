- [VOMS](#voms)
- [For system administrators](#for-system-administrators)
	- [Quickstart](#quickstart)
	- [Prerequisites and recommendations](#prerequisites-and-recommendations)
	- [Recommended deployment scenarios](#recommended-deployment-scenarios)
	- [Installation](#installation)
	- [Configuration](#configuration)
	- [Configuring the VOMS server](#configuring-the-voms-server)
	- [Service operation](#service-operation)
- [Virtual Organization Administration](#virtual-organization-administration)
	- [The voms admin authorization framework](#the-voms-admin-authorization-framework)
	- [Using the admin web application](#using-the-admin-web-application)
	- [Using the command line utilities](#using-the-command-line-utilities)
- [Command line clients](#command-line-clients)
- [Support](#support)
- [License](#license)

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

* Install the EMI release package.
* Install the `emi-voms-mysql` metapackage.
* Set a sensible password for the MySQL root user, as explained in the instructions below.
* Configure the VOMS service using `voms-admin-configure`.

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

Besides the usual OS and EMI release packages, in case of an Oracle based installation you will need the `oracle-instantclient-basic` package, version 10.2.0.4.
```bash
yum localinstall oracle-instantclient-basic-10.2.0.4-1.x86_64.rpm
```

All the other dependencies are resolved by the installation of the VOMS metapackages, i.e.:

* `emi-voms-mysql`, in case of a MySQL installation,
* `emi-voms-oracle`, in case of an Oracle installation.

## Recommended deployment scenarios

A single-node installation, with the hardware recommendations given above should serve well most scenarios. It is not recommended to deploy a large number of VOs (> 20) on a single installation. This is due to an architectural limitation of VOMS (i.e., independent web applications and service for each VO) that will be solved in a future VOMS release.

## Installation

### Repositories

Follow the general EMI installation instructions. VOMS requires that the OS and EPEL repositories are active and correctly configured on the target machine. If Oracle is used, a repository where Oracle packages are available should also be provided. Otherwise Oracle packages need to be installed manually.

### Clean installation

Install the `emi-voms-mysql` metapackage, or `emi-voms-oracle` depending on the database backend you are using
```bash
yum install emi-voms-mysql
```

### Upgrade from gLite 3.2

In order to install the EMI VOMS metapackage you will need a clean SL5 or SL6 X86_64 machine with the EPEL repository configured and the emi release package correctly installed. SL5, as configured by gLite 3.2, is not suitable for installing the EMI VOMS since gLite uses the DAG repository, which is alternative and incompatible with EPEL. Once you have a clean machine configured, install the `emi-voms-mysql` metapackage, without **launching yaim configuration**.

On your existing gLite 3.2 VOMS node dump the VOMS database for all the VOs issuing the following command:
```bash
mysqldump -uroot -p<MYSQL_ROOT_PASSWORD> --all-databases --flush-privileges > voms_database_dump.sql
```

You should now have the mysql daemon installed in your EMI machine (it was installed as a dependency of the `emi-voms-mysql` metapackage). Follow the instructions in this section to properly configure the mysql root account.

Once the root account is configured and working (check that you can login issuing the command `mysql -uroot -p<MYSQL_ROOT_PASSWORD>`), you can restore the VOMS database issuing the following command:
```bash
mysql -uroot -p<PASSWORD> < voms_database_dump.sql
```

Use `voms-admin-configure` to configure the service. Just check that no gLite-specific paths are referenced in your configuration and possibly integrate it with the new options provided by EMI VOMS.

When upgrading an Oracle installation, a database schema upgrade is required when upgrading from gLite 3.2 or EMI 1. The schema upgrade should be performed before running the YAIM configuration following this procedure:

* Backup the contents of the VOMS databases uses the appropriate tools as described in Oracle documentation.
* Run voms-admin-configure upgrade

Reconfigure the services as described above.

There is a known issue with upgrading from gLite 3.2. The AUP may not be shown correctly after upgrade to EMI. After upgrading a gLite 3.2 VOMS Admin the URL pointing to the default AUP text (`/var/glite/etc/voms-admin/vo-aup.txt`) is not upgraded to the new location (`/etc/voms-admin//vo-aup.txt`). This issue lead to an empty AUP shown to the users for the upgraded VOMS. To solve this issue, change the AUP url from the VOMS admin web interface by pointing your browser to: `https://<voms-hostname>:8443/voms/<vo>/aup/load.action`. The default URL for the new aup is: `file:/etc/voms-admin/<vo>/vo-aup.txt`.

### Upgrade from EMI 1 VOMS

* Install the emi-release package for EMI 2.
* Update packages via yum update.
* Restart the services

When upgrading an Oracle installation, follow this procedure:

* Install the emi-release package for EMI 2.
* Update packages via yum update.
* Stop the services (voms and voms-admin)
* Backup the contents of the VOMS databases uses the appropriate tools as described in Oracle documentation.
* Run voms-admin-configure upgrade
* Restart the services

## Configuration

### MySQL configuration

Make sure that the MySQL administrator password that you specify when running `voms-admin-configure` matches the password that is set for the root MySQL account, as `voms-admin-configure` will not set it for you. If you want to set a MySQL administrator password:

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

## Configuring the VOMS server

Run `voms-admin-configure` to configure both voms-admin and voms. The general syntax of the command is
```bash
voms-admin-configure COMMAND [OPTIONS]
```

Available commands are:

* install: is used to configure a VO
* remove: is used to unconfigure a VO
* upgrade: is used to upgrade the configuration of a VO installed with an older version of voms-admin.

Usually, you do not have a dedicated MySQL administrator working for you, so you will use voms-admin tools to create the database schema, configure the accounts and deploy the voms database. If this is the case, you need to run the following command:

```bash
voms-admin-configure install --dbtype mysql
--vo <vo name> 
--createdb 
–deploy-database  
--dbauser <mysql root admin  username>
--dbapwd <mysql root admin  password>
--dbusername <mysql voms username>
--dbpassword  <mysql voms password>
--port <voms core service port>
--smtp-host <STMP relay host>
--mail-from <Sender address for service-generated emails>
```
	
Note that the above command is entered as a single command; it has been broken up into multiple lines for clarity. The command creates and initializes a VOMS database, and configures the VOMS core and admin services that use such database. The required options are described below:

<table>
	<tr>
		<th>Option</th>
		<th>Meaning</th>
	</tr>
	<tr>
		<td>createdb</td>
		<td>This option is MySQL specific and is used to specify that the MySQL database for VOMS must be created by the script.</td>
	</tr>
	<tr>
		<td>deploy-database</td>
		<td>This option tells the script that it must create the tables for VOMS and fill in the necessary bootstrap information (e.g., admin accounts, supported CAs, ...)</td>
	</tr>
	<tr>
		<td>dbauser,dbapwd</td>
		<td>These options are MySQL specific and are used to set the MySQL root user account username and password respectively. These credentials are needed to create the MySQL database for VOMS, and thus required when the createdb option is set. If MySQL is configured with an empty password for the root account, the dbapwd option may be omitted.</td>
	</tr>
	<tr>
		<td>dbusername, dbpassword</td>
		<td>These options are used to specify the MySQL account that VOMS will use when contacting the database. If the createdb option is set, voms-admin creates the account for you.</td>
	</tr>
	<tr>
		<td>port</td>
		<td>This option specifies on which port the VOMS core server will listen for requests.</td>
	</tr>
	<tr>
		<td>mail-from, smtp-host</td>
		<td>These options specify, respectively, the address that must be used for service-generated emails and the SMTP service that must be used to send them.</td>
	</tr>
</table>

An example MySQL VO installation command is shown below:

```bash
/usr/sbin/voms-admin-configure install --dbtype mysql \ 
--vo test_vo_mysql --createdb --deploy-database \ 
--dbauser root --dbapwd pwd \ 
--dbusername voms_admin_20 --dbpassword pwd \ 
--port 54322 --mail-from ciccio@cnaf.infn.it \ 
–smtp-host iris.cnaf.infn.it
```

Oracle VO configuration is different from MySQL configuration. In Oracle you need to setup the database account for VOMS before launching voms-admin configure. Moreover, Oracle instant client libraries must be installed and configured before running voms-admin configuration.

Once you have configured Oracle stuff, you can install a new Oracle VO using the following command:

```bash
voms-admin-configure install --dbtype oracle 
--vo <VO name> 
--dbname <TNS alias of the database backend> 
--deploy-database
--dbusername <voms db account username> 
--dbpassword <voms db account password> 
--port <voms core service port> 
--smtp-host <SMTP relay host> 
--mail-from <Sender address for service-generated emails>
```
Note that the above command is entered as a single command; it has been broken up into multiple lines for clarity. This command is indeed very simliar to the one used to configure a MySQL VO. The main difference lies in the dbname option, that is used to specify the TNS alias for the Oracle database backend. This TNS alias is needed to build the connection string that VOMS will use to communicate with the database backend.Usually, TNS aliases are maintained in the tnsnames.ora file, located in a directory that is usually exported to applications via the TNS_ADMIN Oracle environment variable. For more information regarding TNS aliases, consult the Oracle online documentation (http://www.oracle.com/pls/db102/homepage).

An example Oracle VO installation command is shown below:

```bash
voms-admin-configure install --dbtype oracle \ 
--vo test_vo --dbname test --deploy-database \ 
--dbusername voms_admin_20 --dbpassword pwd \ 
--dbhost datatag6.cnaf.infn.it --port 54321 \ 
--mail-from ciccio@cnaf.infn.it --smtphost iris.cnaf.infn.it
```

`voms-admin-configure` is used also for removing already configured vos

```bash
voms-admin-configure remove --vo VONAME
```

Available options are:

* undeploy-database:	 Undeploys the VOMS database. By default when removing a VO the database is left untouched. All the database content is lost.
* dropdb (MySQL only):	 This flag is used to drop the mysql database schema created for MySQL installations using the --createdb option

## Service operation

To start and stop the VOMS core service for all the vos on the machine, use:
```bash
service voms start
```
while to start and stop a specific vo
```bash
service voms start <vo>
```
The same applies for voms-admin.

### Migration

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

# Virtual Organization Administration

## The voms admin authorization framework

In VOMS-Admin, each operation that access the VOMS database is authorized via the VOMS-Admin Authorization framework. For instance, only authorized admins have the rights to add users or create groups for a specific VO.

More specifically, Access Control Lists (ACLs) are linked to VOMS contexts to enforce authorization decisions on such contexts. In this framework, a Context is either a VOMS group, or a VOMS role within a group. Each Context as an ACL, which is a set of access control entries, i.e., (VOMS Administrator, VOMSPermission) couples.

A VOMS Administrator may be:

* A VO administrator registered in the VO VOMS database;
* A VO user;
* A VOMS FQAN;
* Any authenticated user (i.e., any user who presents a certificate issued by a trusted CA).

A VOMS Permission is a fixed-length sequence of permission flags that describe the set of permissions a VOMS Administrator has in a specific context. The following table explains in detail the name and meaning of these permission flags:

* CONTAINER_READ, CONTAINER_WRITE: These flags are used to control access to the operations that list/alter the VO internal structure (groups and roles list/creations/deletions, user creations/deletions).
* MEMBERSHIP_READ, MEMBERSHIP_WRITE: These flags are used to control access to operations that manage/list membership in group and roles.
* ATTRIBUTES_READ,ATTRIBUTES_WRITE: These flags are used to control access to operations that mange generic attributes (at the user, group, or role level).
* ACL_READ,ACL_WRITE,ACL_DEFAULT: These flags are used to control access to operations that manage VO ACLs and default ACLs.
* REQUESTS_READ, REQUESTS_WRITE: These flags are used to control access to operations that manage subscription requests regarding the VO, group membership, role assignment etc...
* PERSONAL_INFO_READ, PERSONAL_INFO_WRITE: The flags are used to control access to user personal information stored in the database.
* SUSPEND: This flag controls who can suspend other users.

Each operation on the VOMS database is authorized according to the above set of permissions, i.e., whenever an administrator tries to execute such operation, its permissions are matched with the operation's set of required permission in order to authorize the operation execution.

Children groups, at creation time, inherit parent's group ACL. However, VOMS Admin implements an override mechanims for this behaviour via Default ACLs. When the Default ACL is defined for a group, children groups inherit the Default ACL defined at the parent level instead of the parent's group ACL. So, Default ACLs are useful only if an administrator wants the ACL of children groups to be different from the one of the parent's group.

In the following, we describe the required permissions for the most comon voms-admin operations according to this notation:

<table>
  <tr>
    <th>Symbol</th>
		<th>Meaning</th>
  </tr>
  <tr>
    <td>/vo</td>
		<td>The VO root group</td>
  </tr>
  <tr>
    <td>(g,R)</td>
		<td>The context identified by role R within group g</td>
  </tr>
  <tr>
    <td>(g ➝ g')</td>
		<td>All the voms groups that lie in the path from group g to group g' included according to the parent-child relationship defined between voms group</td>
  </tr>
  <tr>
    <td>r,w,d,s</td>
		<td> Read permission, Write permission, default permission (applies only to ACL permissions), suspend permission</td>
  </tr>
  <tr>
    <td>parent(g)</td>
		<td>Group g's parent group</td>
  </tr>
  <tr>
    <td>C:, M:, Attrs:, Acl:, Req:, PI:</td>
		<td>Container, Membership, Attributes, ACL, Requests and Personal Information permissions short names</td>
  </tr>
</table>

The table below lists operations on the left and required permissions on the right, expressed in the form of (VOMSContext, VOMSPermission) couples.

<table>
  <tr>
    <th>Operation</th>
		<th>Required permissions</th>
		<th>Explanation</th>
  </tr>
  <tr>
    <td>Create/delete user</td>
		<td>(/vo,C:rw M:rw)</td>
		<td>Container and membership read and write access on the root group</td>
  </tr>
  <tr>
    <td>Create/delete group g</td>
		<td>(/vo,C:rw) , (/vo → parent(parent(g)), C:r) , (parent(g), C:rw)</td>
		<td> Container rw access on the root group, container read access on all to groups leading to g's parent group and Container rw access in g's parent group</td>
  </tr>
	<tr>
    <td>List group g subgroups</td>
		<td>(/vo → g, C: r)</td>
		<td>Container read access on all the groups leading to g
		</td>
  </tr>
	<tr>
    <td>Create/delete role</td>
		<td>(/vo, C:rw)</td>
		<td>Container read/write access on the VO root group</td>
  </tr>
	<tr>
    <td>List VO roles</td>
		<td>(/vo, C:r)</td>
		<td>Container read access on the VO root group</td>
  </tr>
	<tr>
    <td>Add remove/member to group g</td>
		<td>(/vo → parent(parent(g)), C:r), (g, M:rw)</td>
		<td>Container read access on all the groups leading to g's parent, and Membership rw access on g
		</td>
  </tr>
	<tr>
    <td>List group g members</td>
		<td>(/vo → parent(parent(g)), C:r), (g, M:r)</td>
		<td>Container read access on all the groups leading to g's parent and Membership read access on g</td>
  </tr>
	<tr>
    <td>Assign/dismiss role R in group g</td>
		<td>(/vo → parent(parent(g)), C:r), ((g,R), M:rw)</td>
		<td>	 Container read access on all the groups leading to g's parent and Membership rw access on role R within g</td>
  </tr>
	<tr>
    <td>List members wirh role R in group g</td>
		<td>(/vo → parent(parent(g)), C:r), ((g,R), M:r)</td>
		<td>Container read access on all the groups leading to g's parent and Membership read access on role R within g</td>
  </tr>
	<tr>
    <td>Set/delete user generic attribute</td>
		<td>(/vo, Attrs:rw)</td>
		<td>Attribute rw access on the VO root group</td>
  </tr>
	<tr>
    <td>List user generic attributes</td>
		<td>(/vo, Attrs: r)</td>
		<td>Attribute read access on the VO root group
		</td>
  </tr>
	<tr>
    <td>List group g generic attributes</td>
		<td>(/vo → parent(parent(g)), C:r), (/vo, Attrs:r), (g, Attrs:r)</td>
		<td>Container read access on all the groups leading to g's parent, Attributes read access on the VO root group and on group g</td>
  </tr>
	<tr>
    <td>Set/delete group g attributes</td>
		<td>(/vo → parent(parent(g)), C:r), (/vo, Attrs:rw), (g, Attrs:rw)</td>
		<td>Container read access on all the groups leading to g's parent, Attributes read access on the VO root group and on group g</td>
  </tr>
	<tr>
    <td>Set/delete role R attributes within group g</td>
		<td>(/vo → parent(parent(g)), C:r), (/vo, Attrs:rw), ((g,R), Attrs:rw)</td>
		<td>Container read access on all the groups leading to g's parent, Attributes rw access on the VO root group and on role R withing g</td>
  </tr>
	<tr>
    <td>Edit ACL for group g</td>
		<td>(/vo → parent(parent(g)), C:r), (g, ACL:rw)</td>
		<td>Container read access on all the groups leading to g's parent, ACL rw access on group g</td>
  </tr>
	<tr>
    <td>Edit ACL for group g</td>
		<td>(/vo → parent(parent(g)), C:r), (g, ACL:rw)</td>
		<td>Container read access on all the groups leading to g's parent, ACL rw access on group g</td>
  </tr>
	<tr>
    <td>List ACL for group g</td>
		<td>(/vo → parent(parent(g)), C:r), (g, ACL:r)</td>
		<td>Container read access on all the groups leading to g's parent, ACL read access on group g</tr>
	<tr>
    <td>Suspend a user</td>
		<td>(/vo, s)</td>
		<td>Suspend flag on the VO root group</td>
  </tr>
</table>

## Using the admin web application

The VOMS-Admin web application provides a usable and intuitive interface towards VO management tasks. A screenshot of the main page of the web application is given above.

![Alt text](https://wiki.italiangrid.it/twiki/pub/VOMS/VOMSAdminUserGuide/webui1.png)

In the top part of the page, the header provides information about the current user accessing the interface and the name of the VO that is being managed. The two navigations bars provide access to the main sections of the web application.

In the top part of the page, the header provides information about the current user accessing the interface and the name of the VO that is being managed. The two navigations bars provide access to the main sections of the web application.

### The Home page

By clicking on the home link in the main navbar one can reach his home page.

If the current client has administrator rights, he/she will be directed to the admins home page. User requests for membership and group/role assignments can be managed from this page, as shown in the image below.

![Alt text](https://wiki.italiangrid.it/twiki/pub/VOMS/VOMSAdminUserGuide/admin-home.png)

An administrator that is also a VO user will have a link to his user home page in the upper right part of the page.

If the current client has not admin rights, the VO user home page shows information about the user membership. From this page, the user can request group membership and role assignment and update his personal information. The page also shows information about AUP acceptance records and an history record of user's requests.

![Alt text](https://wiki.italiangrid.it/twiki/pub/VOMS/VOMSAdminUserGuide/user-home.png)

VO members can request the addition of a new certificate to their membership by clicking on the "Request new certificate" button in the Certificates panel, as shown in the picture below:

![Alt text](https://wiki.italiangrid.it/twiki/pub/VOMS/VOMSAdminUserGuide/user-request-cert-2.png)

The member can upload a PEM encoded certificate or type its certificate subject and select the CA subject from the certificate request page, pictured below:

![](https://wiki.italiangrid.it/twiki/pub/VOMS/VOMSAdminUserGuide/request-cert-page.png)

The certificate subject should be entered following the usual /-separated openssl rendering, like in:

/C=IT/O=INFN/OU=Personal Certificate/L=CNAF/CN=Andrea Ceccanti
After this step a notification is sent to the VO admin who has to approve the member's request. The user will be informed via email of the VO admin decision on the request.

### Managing users

The user management section of the VOMS-Admin web interface allows administrators to manage all the information regarding VO membership, i.e., membership status, certificates, groups, roles, generic attributes etc.

It is now possible to suspend users. Suspended users will still be part of the VO, but will not be able to obtain VOMS attribute certificates from the VOMS server.

When suspending a user a reason for the suspension must be given. This reason will be included in a supension notification that will be sent to the user, and shown at `voms-proxy-init` time to suspended users that attempt to get a VOMS proxy.

### ACL Management

The ACL link the navigation bar leads to the ACL management page. The ACL management pane displays ACL entries in the form of (Voms Administrator, Set of permissions) couples. The display uses the compact representation for VOMS permissions that has been already introduced earlier.

![](https://wiki.italiangrid.it/twiki/pub/VOMS/VOMSAdminUserGuide/acl-management.png)

ACL entries can be added to ACL or default ACLs by clicking on the “add entry” link. Permissions can be set for:

* VO users;
* non VO users;
* Anyone having a specific role within a specific group;
* Anyone belongin to a specific VO group;
* Any authenticated user, i.e., everyone with a certificate issued by a trusted CA

Entries added to a group ACL can be propagated to existing context's ACLs by ticking the “Propagate to children context” tick box at the bottom of the page. Similarly, when editing or deleting an ACL entry from a group ACL, it is possible to propagate the deletion or editing to children groups by selecting the “Propagate to children context" tick box.

![](https://wiki.italiangrid.it/twiki/pub/VOMS/VOMSAdminUserGuide/add-ace.png)

### Managing VOMS generic attributes

Generic attributes (GAs) are (name, value) pairs that that can be assigned to VO users and that end up in the Attribute Certificate issued by VOMS. GAs extend the range of attributes that VOMS can issue besides Fully Qualified Attributes Names (FQAN), i.e., allow VOMS to issue any kind of VO membership information that can be expressed as (name, value) pairs. Such information can then be leveraged by Grid applications to take authorization decisions.

For their nature, GAs are issued to VO users. VOMS however provides a way to quickly assign GAs to all the VO members that belong to a specific VOMS group or that are assigned a specific VOMS role within a group. For this reason, you find GA management in user, group and role management pages in VOMS Admin.

To assign GA to users, the VO admin must first create the corresponding Generic Attribute class. This Generic Attribute class is used to define the name and possibly a description for the GA. VOMS Admin also implements a configurable uniqueness check on GA values that can be set when creating a GA class. This uniqueness check ensures that two users cannot share the same value for a specific GA. This check is enforced at the GA class level, so you can have GAs that are checked for uniqueness and others that allow users to share the same value for the same GA.

#### Generic Attribute classes management

The GA classes management page can be reached by clicking on the “Attributes” link in the navbar, and then clicking on the “Manage attribute classes” link. GA classes can then be created, specifying the GA name, description and whether uniqueness must be enforced on the GA values assigned directly to users.

![](https://wiki.italiangrid.it/twiki/pub/VOMS/VOMSAdminUserGuide/ga-classes.png)

#### Managing GAs at the user, group and role level

Once a GA class has been created, GA values can be assigned to users, groups and role within groups. As mentioned above, when one GA is assigned directly to a user, the (name,value) couple is added by VOMS to the attribute certificate returned to user. When a GA is assigned to a group, or role within a group, such (name, value) pair ends up in the Attribute Certificate of all the VO members belonging to that group (or that have such role within a group).

#### Search GA assignments

VOMS Admin implements search over user GA assignments, so that an administrator can easily know the status of GA assignments. The search functions deal only with GA assigned directly to user, i.e., group and role assignements search and centralized display is currently not supported.

![](https://wiki.italiangrid.it/twiki/pub/VOMS/VOMSAdminUserGuide/ga-assignments.png)

### Acceptable Usage Policies (AUP) management

Starting with version 2.5, VOMS Admin implements AUP management. AUP acceptance records are linked to each VO membership, to keep track of which version of the AUP was accepted and when.

Each AUP in VOMS Admin has a reacceptance period. Each user's acceptance record is checked against this period and if the record has expired the user is requested to sign again the AUP.

When the user fails to sign the AUP in the allotted time, he/she is suspended.

Finally, VOMS admin provides the possibility to request re-acceptance from users at any time.

#### How to disable AUP management

AUP management can be disabled by disabling the VOMS Admin registration service. To disable the registration service add the --disable-webui-requests flag when configuring a VO with the voms-admin-configure command, or put the following setting:
voms.request.webui.enabled = false
in the /etc/voms/<vo_name>/voms.service.properties.

#### AUP management page

![](https://wiki.italiangrid.it/twiki/pub/VOMS/VOMSAdminUserGuide/aup-management.png)

From the AUP management page is possible to add/remove new versions of the AUP, update the AUP reacceptance period, set which of the managed version is the active one (i.e., the one presented to VO users at signing time) and request reacceptance of the current version from users.

For VOMS Admin basically an AUP is the URL of a text file, so any file on the local filesystem or on a remote web server can be used for the AUP text.

#### Setting the VO AUP url at VO configuration time

The voms-admin-configure --vo-aup-url option can be used to set the URL for the initial version of the VO acceptable usage policy. If this option is not set a template vo-aup file will be created in vo runtime configuration directory /etc/voms-admin/<vo-name>/vo-aup.txt

### The Configuration Info section

The Configuration info section shows configuration information useful for voms clients, like the vomses string for the VO or a mkgridmap example configuration.

![](https://wiki.italiangrid.it/twiki/pub/VOMS/VOMSAdminUserGuide/conf-section.png)

### The Other VOs section

This section provides links to the other VOs configured on the server.

## Using the command line utilities

### The voms-db-util.py command

The `voms-db-deploy.py` command is used to manage the deployment of the VOMS database and to add/remove administrators without requriing voms-admin VOs to be active.

```bash
[root@emitestbed18 ~]# voms-db-deploy.py 

Usage:
    
voms-db-deploy.py deploy --vo [VONAME]
voms-db-deploy.py undeploy --vo [VONAME]
voms-db-deploy.py upgrade --vo [VONAME]

voms-db-deploy.py add-admin [--ignore-cert-email] --vo [VONAME] --cert [CERT_FILE]
voms-db-deploy.py add-admin --vo [VONAME] --dn [ADMIN_DN] --ca [ADMIN_CA] --email [EMAILADDRESS]

voms-db-deploy.py remove-admin --vo [VONAME] --cert [CERT_FILE]
voms-db-deploy.py remove-admin --vo [VONAME] --dn [ADMIN_DN] --ca [ADMIN_CA]

voms-db-deploy.py check-connectivity --vo [VONAME]

voms-db-deploy.py grant-read-only-access --vo [VONAME]
```

### The voms-admin command line client

VOMS Admin comes with a python command line client utility, called voms-admin, that can be used to perform most of the operations on the VOMS database that are implemented by the Web interface.

`voms-admin` uses the UNIX effective user ID to choose which X509 credential it must use to connect to a (possibly remote) VOMS Admin instance. When ran as root, `voms-admin` uses the host credentials found in /etc/gridsecurity. When running as a normal user, `voms-admin does the following:`

* if the X509_USER_PROXY environment variable is set, voms-admin uses the credentials pointed by such environment variable,
* otherwise If a proxy exists in /tmp, the proxy is used,
* otherwise if the X509_USER_CERT environment variable is set, voms-admin uses the credentials pointed by X509_USER_CERT and X509_USER_KEY environment variables,
* otherwise the usercert.pem and userkey.pem credentials from the $HOME/.globus are used.

A user can get the list of supported commands by typing:

```bash
voms-admin --list-commands
```

The output will be something like:

```bash
Supported commands list:

ROLE ASSIGNMENT COMMANDS:

  assign-role
  dismiss-role
  list-users-with-role
  list-user-roles

ROLE MANAGEMENT COMMANDS:

  list-roles
  create-role
  delete-role

ATTRIBUTE CLASS MANAGEMENT COMMANDS:

  create-attribute-class
  delete-attribute-class
  list-attribute-classes

GROUP MEMBERSHIP MANAGEMENT COMMANDS:

  add-member
  remove-member
  list-members

USER MANAGEMENT COMMANDS:

  list-users
  create-user
  delete-user

ACL MANAGEMENT COMMANDS:

  get-ACL
  get-default-ACL
  add-ACL-entry
  add-default-ACL-entry
  remove-ACL-entry
  remove-default-ACL-entry

GENERIC ATTRIBUTE ASSIGNMENT COMMANDS:

  set-user-attribute
  delete-user-attribute
  list-user-attributes
  set-group-attribute
  set-role-attribute
  delete-group-attribute
  list-group-attributes
  list-role-attributes
  delete-role-attribute

GROUP MANAGEMENT COMMANDS:

  list-groups
  list-sub-groups
  create-group
  delete-group
  list-user-groups
```

Detailed help about individual commands can be obtained issuing the following command:

```bash
voms-admin --help-command <command name>
```

The help message contains examples for typical use cases. For example, asking help about the create-user command produces the following output:

```bash
$ voms-admin --help-command create-user

create-user CERTIFICATE.PEM
	
        Registers a new user in VOMS. 
        
        If you use the --nousercert  option, then four parameters are 
        required (DN CA CN MAIL) to create the user. 
        
        Otherwise these parameters are extracted automatically from the
        certificate. 
        
        Examples: 
        
        voms-admin --vo test_vo create-user .globus/usercert.pem 
        
        voms-admin --nousercert --vo test_vo create-user \ 
        'My DN' 'My CA' 'My CN' 'My Email'
```

A user can get help about all the commands provided by voms-admin by typing:

```bash
voms-admin --help-commands
```
# Command line clients

## User credentials

While user credentials may be put anywhere, and then their location passed to `voms-proxy-init` via the appropriate options, there are obviously default values.
User credentials should be put in the .globus subdirectory. Both PKCS12 and PEM formatted credentials are okay. The default name for the PKCS12 are usercert.p12 or usercred.p12, while usercert.pem and userkey.pem are the default names for the PEM formatted one. In case both the PEM and PKCS12 formats are present, PEM takes precedence. The user certiﬁcate should at the most have permission 600, while the user key shoud be 400.

## Creating a proxy

This command `voms-proxy-init` is used to contact the VOMS server and retrieve an AC containing user attributes that will be included in the proxy certiﬁcates.

```bash
$ voms-proxy-init --voms voname
```

where voname is the name of the VO to which the user belongs. This will create a proxy containing all the groups
to which the user belongs, but none of the roles. Also, the -voms option may be speciﬁed multiple times in case the
user belongs to more than one VO. It is also possible to omit the –voms option entirely. This will however result in
the creation of a completely globus-standard proxy, and is not advised since such proxies will not be usable under 
gLite 3.0.0 and beyond.

As stated above, no roles are ever include in proxy by default. In case they are needed, they must be
explicitly requested. For example, to request the role sgm in the /test/italian group, the following
syntax should be used:
```bash
$ voms-proxy-init --voms test:/test/italian/Role=sgm
```

thus obtaining a role that will be included in the AC, in addition to all the other information that will be
normally present. In case multiple roles are needed, the -voms option may be used several times.

By default, all FQANs explicitly requested on the command line will be present in the returned credentials,
if they were granted, and in the exact order speciﬁed, with all other FQANs following in an unspeciﬁed
ordering. If a speciﬁc order is needed, it should be explicitly requested via the -order option. For
example, the following command line:

```bash
$ voms-proxy-init --voms test:/test/Role=sgm --order /test
```

asks for the Role sgm in the root group, and speciﬁes that the resulting AC should begin with membership
in the root group instead, while posing no requirements on the ordering of the remaining FQANs. This
also means that with the above command line there is no guarantee that the role will end up as the second
FQAN. If this is desired, use the following command line instead:
```bash
$ voms-proxy-init --voms test:/test/Role=sgm --order /test --order /test/Role=sgm
```

The validity of an AC created by VOMS will generally be as long as the proxy which contains it. However,
this cannot always be true. For starters, the VOMS server is conﬁgured with a maximum validity for all
the ACs it will create, and a request to exceed it will simply be ignored. If this happens, the output of
voms-proxy-init will indicate the fact.

For example, in the following output (slightly reformatted for a shorter line then on screen):

```bash
$ voms-proxy-init --voms valerio --vomslife 50:15
Enter GRID pass phrase:
Your identity: /C=IT/O=INFN/OU=Personal Certificate/L=CNAF/CN=Vincenzo Ciaschini
Creating temporary proxy .................................... Done
Contacting datatag6.cnaf.infn.it:50002
[/C=IT/O=INFN/OU=Host/L=CNAF/CN=datatag6.cnaf.infn.it] "valerio" Done
Warning: datatag6.cnaf.infn.it:50002:
The validity of this VOMS AC in your proxy is shortened to 86400 seconds!
Creating proxy ......................................... Done
Your proxy is valid until Fri Sep 8 01:55:34 2006
```

You can see that the life of the voms AC has been clearly shortened to 24 hours, even though 50 hours
and 15 minutes had been requested.
If your certiﬁcate is not in the default place, you may specify it explicitly by using the –cert and –key
options, like in the following example:

```bash
voms-proxy-init --voms valerio --cert \$HOME/cert.pem --key \$HOME/key.pem
```

Finally, in case several options have to be speciﬁed several times, proﬁles can be created. For examples:

```bash
[marotta@datatag6 marotta]$ cat voms.profile
--voms=valerio
--lifetime=50:15
--cert=/home/marotta/mycert.pem
--key=/home/marotta/mykey.pem
--order=/valerio/group1
```

followed by:

```bash
[marotta@datatag6 marotta]$ voms-proxy-init --conf voms.profile
[marotta@datatag6 marotta]$ voms-proxy-init --voms valerio \
--lifetime 50:15 --cert /home/marotta/mycert.pem \
--key /home/marotta/mykey.pem --order /valerio/group1
```

with the obvious advantages of being much less error-prone

See `voms-proxy-init --help` or the man page for a complete list of available options.

## Showing proxy information

Once a proxy has been created, the voms-proxy-info command allowes the user to retrieve several
information from it. The two most basic uses are:

```bash
$ voms-proxy-info
subject : /C=IT/O=INFN/OU=Personal Certificate/L=CNAF/CN=Vincenzo Ciaschini/CN=proxy
issuer : /C=IT/O=INFN/OU=Personal Certificate/L=CNAF/CN=Vincenzo Ciaschini
identity : /C=IT/O=INFN/OU=Personal Certificate/L=CNAF/CN=Vincenzo Ciaschini
type : proxy
strength : 512 bits
path : /tmp/x509up_u502
timeleft : 10:33:52
```

which, as you can see, prints the same information that would be printed by a plain grid-proxy-info,
and then there is:

```
$ voms-proxy-info --all
subject : /C=IT/O=INFN/OU=Personal Certificate/L=CNAF/CN=Vincenzo Ciaschini/CN=proxy
issuer : /C=IT/O=INFN/OU=Personal Certificate/L=CNAF/CN=Vincenzo Ciaschini
identity : /C=IT/O=INFN/OU=Personal Certificate/L=CNAF/CN=Vincenzo Ciaschini
type : proxy
strength : 512 bits
path : /tmp/x509up_u502
timeleft : 11:59:59
=== VO valerio extension information ===
VO : valerio
subject : /C=IT/O=INFN/OU=Personal Certificate/L=CNAF/CN=Vincenzo Ciaschini
issuer : /C=IT/O=INFN/OU=Host/L=CNAF/CN=datatag6.cnaf.infn.it
attribute : /valerio
attribute : /valerio/asdasd
attribute : /valerio/qwerty
attribute : attributeOne = 111 (valerio)
attribute : attributeTwo = 222 (valerio)
timeleft : 11:59:59
uri : datatag6.cnaf.infn.it:15000
```

which prints everything that there is to know about the proxy and the included ACs. Several options enable
the user to select just a subset of the information shown here.

See `voms-proxy-info --help` or the man page for a complete list of available options.

## Destroying a proxy

The `voms-proxy-destroy` command erases an existing proxy from the system. Its basic use is:

```bash
$ voms-proxy-destroy
```

See `voms-proxy-destroy --help` or the man page for a complete list of available options.

# Support

Having problem with VOMS? Submit a ticket in
[GGUS](https://ggus.eu/pages/ticket.php) targeted at the VOMS EMI support unit.

# License

Licensed under the Apache License, Version 2.0 (the "License"); you may not use
this project except in compliance with the License. You may obtain a copy of
the License at http://www.apache.org/licenses/LICENSE-2.0.

Unless required by applicable law or agreed to in writing, software distributed
under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
CONDITIONS OF ANY KIND, either express or implied. See the License for the
specific language governing permissions and limitations under the License.
