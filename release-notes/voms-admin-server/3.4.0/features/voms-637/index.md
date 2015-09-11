---
layout: default
title: VOMS Admin server v. 3.4.0 - VOMS Admin Audit log
---

- [VOMS-637](https://issues.infn.it/jira/browse/VOMS-637) - VOMS Admin should maintain an audit log in the database

#Audit log

An audit log is a security-relevant chronological set of records that provide documentary evidence of the sequence of activities that have affected at any time a specific operation, procedure, or event. Audit records typically result from activities such as transactions or communications by individual people, systems, accounts, or other entities.

From [VOMS Admin 3.4.0][vomsadmin340], administrators can read all the relevant events into a brand new section `Audit log`. The VOMS Admin audit log allows administrators to keep track of all the events occurred. The events logged are the following:

- Request's status changes for:
    - VO membership: submitted, approved, rejected, expired, canceled, confirmed
    - Group or role membership: submitted, approved, rejected
    - Certificate: submitted, approved, rejected
- User's events:
    - user status changes: created, deleted, restored, suspended
    - personal information updated 
    - membership:
        - role assigned or dismissed
        - user added to group
        - user removed from group
        - user membership approved
        - membership expiration date updated
        - membership expired
    - attribute set or deleted
    - personal certificate addiction: added, suspended, removed, restored.
    - AUP: signature requested, AUP signed, task assigned, task reminder.
    - OrgDb id updated
- VO's events:
    - administrator created or deleted
    - ACL created, updated or deleted
    - attribute description created or deleted
    - AUP 
        - created
        - period changed
        - version created, updated, deleted or set active
        - triggered forced re-acceptance
    - group 
        - created or deleted
        - description updated
        - attribute set or deleted
    - role
        - created or deleted
        - attribute set or deleted
    - group-manager role created or deleted

The following picture shows an example of the audit log page:

{% include image.html url="images/audit-log.jpg" description="<b>Fig.1</b>: Audit log page example." %}

All the events occurred between 09/01/2015 and 09/11/2015 are listed. 

Administrators can also filter the events showed by type or principal, specifying a string which allows '%' character as a wildcard. For example, the following picture shows the above audit log filtered by selecting all the principal that contains the string 'Vianello':

{% include image.html url="images/audit-log-filtered.jpg" description="<b>Fig.2</b>: Audit log page example with a wildcard applied." %}

All the events whose contain the string 'Vianello' and occurred between 09/01/2015 and 09/11/2015 are listed. 

[vomsadmin340]: {{site.baseurl}}/release-notes/voms-admin-server/3.4.0/