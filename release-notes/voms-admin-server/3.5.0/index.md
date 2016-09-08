---
layout: default
title: VOMS Admin server v. 3.5.0
rfcs:
  - id: VOMS-741
    title: Supend user/certificate dialog should not allow an empty suspensionReason
  - id: VOMS-740
    title: VOMS Admin certificate remove operation should be protected by a confirmation dialog
  - id: VOMS-739
    title: VOMS Admin should give users the possiblity of removing unused certificates
  - id: VOMS-738
    title: Add ACL can generate an audit log message that does not fit in the audit_log_event data table
  - id: VOMS-734
    title: Properly restore VO users if their membership is restored in the HR db after a membership expiration
  - id: VOMS-733
    title: Improve display of user certificate information
  - id: VOMS-731
    title: VOMS Admin notification events should be included in the audit log
  - id: VOMS-730
    title: VOMS Admin does not send AUP reminders
  - id: VOMS-729
    title: AUP reminder interval is not parsed correctly from configuration
  - id: VOMS-728
    title: Ensure consistent certificate-based lookup behaviour
  - id: VOMS-676
    title: voms-configure does not handle passwords correctly
features:
  - id: VOMS-743
    title: Implement full-text search on audit_log event data points
  - id: VOMS-742
    title: Allow membership that do not expire
  - id: VOMS-732
    title: The VOMS web app should not disclose details regarding the membership expiration or Sign AUP status to unprivileged users
  - id: VOMS-725
    title: "VOMS Admin: more precise display of time to expiration for membership and AUP signature expiration"
  - id: VOMS-626
    title: VOMS Admin should persist notifications in the database
---

# VOMS Admin server v. 3.5.0

This release provides fixes to some outstanding bugs and some improvements:

- A bug that prevented the correct sending of AUP reminders has been fixed
- Notifications are now stored in the VOMS database; this is especially
  targeted at clustered VOMS Admin deployments and avoids duplicate delivery of
  notifications to users and administrators 
- The audit log panel is now paginated and supports full-text search on audit
  log events
- VOMS Admin now supports membership that do not expire

The list of full bug fixes and new features is listed below.

### Bug fixes

{% include list-rfcs.liquid %}

### New features and improvements 

{% include list-features.liquid %}

### Installation and configuration

#### Upgrade from VOMS Admin Server >= 3.2.0

A [database upgrade][db-upgrade] and a [reconfiguration][reconf] (in this order) are
required to upgrade to VOMS Admin server 3.5.0.

#### Upgrade from earlier VOMS Admin Server versions

First upgrade to VOMS Admin version [3.2.0][voms-admin-320-rn] and then to 3.5.0.

#### Clean install

Follow the instructions in the VOMS [System Administrator Guide][sysadmin-guide].

[voms-website]: http://italiangrid.github.io/voms
[sysadmin-guide]:{{site.baseurl}}/documentation/sysadmin-guide/3.0.8
[voms-admin-guide]: {{site.baseurl}}/documentation/voms-admin-guide/3.5.0
[reconf]: {{site.baseurl}}/documentation/sysadmin-guide/3.0.8/#reconf
[db-upgrade]: {{site.baseurl}}/documentation/sysadmin-guide/3.0.8/#db-upgrade
[voms-admin-320-rn]: {{site.baseurl}}/release-notes/voms-admin-server/3.2.0
[voms-admin-332-rn]: {{site.baseurl}}/release-notes/voms-admin-server/3.3.2
