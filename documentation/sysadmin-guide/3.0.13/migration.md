---
layout: default
version: 3.0.13
title: VOMS migration guide
---

# VOMS services migration reference

{% include sysadmin-guide-version.liquid %}

## Migration <a name="Migration">&nbsp;</a>

In order to migrate VOMS to a different machine, the following items will need to be migrated:

1. The configuration
1. The database content. This holds only if VOMS was configured to access a local database instance. If a remote database is used for VOMS only the configuration will need to be migrated to the new installation.

### Configuration  migration
To migrate VOMS configuration, archive the contents of the following directories and move the archive to the new installation:

```
/etc/voms/*
/etc/voms-admin/*
```

### Database migration

In order to dump the contents of the VOMS datbase issue the following command on the original VOMS installation machine:

```
mysqldump -uroot -p<MYSQL_ROOT_PASSWORD> --all-databases --flush-privileges > voms_database_dump.sql
```

This database dump contains all the VOMS data and can be moved to the new VOMS installation machine.

To restore the database contents on the new VOMS installation machine, ensure that:

1. mysql-server is up & running
1. the password for the MySQL root account is properly configured (see the [configuration section](#Configuration) for more details)

The database content can then be restored using the following command:
```
mysql -uroot -p<PASSWORD> < voms_database_dump.sql
```
