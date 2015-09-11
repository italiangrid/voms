---
layout: default
title: VOMS OrgDB plugin
---


##VOMS OrgDB plugin

The VOMS OrgDB plugin provides integration with the CERN organizational database.

When OrgDB integration is active:

- registration requests are validated so that only applicants present in the OrgDB can apply for VO membership.
- VO membership expiration time is linked to OrgDB membership expiration.

###Enabling the plugin

The plugin configuration is not currently provided by `voms-admin-configure` or the voms YAIM module.

Assuming the VO where you want to enable the OrgDB plugin is already configured, you will need to do the following changes to the configuration:

- Edit the `voms.service.properties` file for the VO to enable the plugin.
- Create the file orgdb.properties where orgdb database connection properties will be configured.
Both files can be found in the `/etc/voms-admin/<vo-name>` directory.

####Changes to the voms.service.properties file

Add the following lines at the bottom of the `voms.service.properties` file:

	## External validation plugin options
	voms.external-validators = orgdb
	voms.ext.orgdb.configClass = org.glite.security.voms.admin.integration.orgdb.OrgDBConfigurator
	voms.ext.orgdb.experimentName = ATLAS
	voms.ext.orgdb.membership_check.period = 30

####The orgdb.properties configuration file

The orgdb.properties configuration provides hibernate settings to connect to the OrgDB Oracle database:

	hibernate.connection.driver_class= oracle.jdbc.driver.OracleDriver
	hibernate.connection.url= jdbc:oracle:oci:<the orgdb alias here>
	hibernate.dialect= org.hibernate.dialect.Oracle10gDialect

	hibernate.connection.username= orgdb_username
	hibernate.connection.password= orgdb_password

	hibernate.c3p0.acquire_increment=1
	hibernate.c3p0.idle_test_period=100
	hibernate.c3p0.min_size=5
	hibernate.c3p0.max_size=100
	hibernate.c3p0.max_statements=0
	hibernate.c3p0.timeout=100

###Troubleshooting

Check the voms-admin log in `/var/log/tomcat{5|6}`. In case of successful configuration you will see something like:

	2012-11-27 08:06:08.582Z - INFO [OrgDBConfigurator] - Connection to the OrgDB database is active.
	2012-11-27 08:06:08.583Z - INFO [OrgDBConfigurator] - Setting OrgDB experiment name: ATLAS
	2012-11-27 08:06:08.595Z - INFO [DefaultMembershipCheckBehaviour] - Expired users will be suspended after a grace period of 7 days.
	2012-11-27 08:06:08.601Z - INFO [OrgDBConfigurator] - OrgDB request validator registered SUCCESSFULLY.
	2012-11-27 08:06:08.604Z - INFO [VOMSExecutorService] - Scheduling task OrgDBMembershipSynchronizationTask with period: 30 seconds
	2012-11-27 08:06:08.604Z - INFO [PluginManager] - 'orgdb' plugin configured SUCCESSFULLY.