---
layout: default
title: VOMS Admin server v. 3.4.0 - VOMS and external HR database linked through HR member id
---

[VOMS-650](https://issues.infn.it/jira/browse/VOMS-650) - VOMS should leverage HR member id instead of primary email for linking VOMS and HR membership

## VOMS and external HR database linked through HR member id

VOMS can be linked to an external HR (Human Resources) database, like the CERN organizational database (see [VOMS OrgDB plugin]({{site.baseurl}}/documentation/sysadmin-guide/3.0.5/orgdbplugin.html)).

Before [VOMS Admin 3.4.0][vomsadmin340], the integration between the VOMS and a HR database was made through th eprimary email field. But this was not stable enough.
Since [VOMS Admin 3.4.0][vomsadmin340] this integration leverages the HR database user id instead, which is supposed to be stable and cannot be changed by users. This wouldn't affect the registration flow but would allow us to synchronize the email in VOMS with the mail in the HR, and avoid some confusion for the users.

[vomsadmin340]: {{site.baseurl}}/release-notes/voms-admin-server/3.4.0/