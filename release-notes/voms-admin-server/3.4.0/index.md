---
layout: default
title: VOMS Admin server v. 3.4.0
rfcs:
- id: VOMS-658
  title: List users should return all certificates for registered VO members
- id: VOMS-657
  title: Form validation for the Institute field should be disabled when HR DB integration is on
- id: VOMS-656
  title: Suspended users end up in Gridmap files
- id: VOMS-645
  title: Force users to include a textual motivation for group and role requests
- id: VOMS-640
  title: VOMS Admin sessions expire in two minutes
- id: VOMS-636
  title: VOMS admin change reacceptance period should be protected by a confirmation dialog
- id: VOMS-631
  title: VOMS Admin RPM should depend on Java 8
- id: VOMS-629
  title: Improve VOMS Admin request certificate page
- id: VOMS-628
  title: VOMS Admin pending request page should provide easy access to requestor email address
- id: VOMS-625
  title: Cumulative permissions do not grant all intended privileges
- id: VOMS-524
  title: Include Orgdb configuration documentation in VOMS administrator guide
features:
- id: VOMS-675
  title: Provide a VO member targeted VOMS Admin guide
- id: VOMS-655
  title: Group-Manager role to grant group membership request rights
- id: VOMS-654
  title: VOMS should provide a page that displays detailed information about the certificate used to connect to the service
- id: VOMS-650
  title: VOMS should leverage HR member id instead of primary email for linking VOMS and HR membership
- id: VOMS-649
  title: Add ability to edit group description
- id: VOMS-635
  title: VOMS triggerReacceptance confirm dialog should shield from user mistakes
- id: VOMS-634
  title: VOMS Admin handle request page should show only requests that can be handled by an administrator
- id: VOMS-633
  title: Add ability to handle multiple requests page from VOMS Admin "Handle requests" page
- id: VOMS-129
  title: VOMS admin provides configurable notification interval for Sign AUP messages
---

# VOMS Admin server v. 3.4.0

This release fixes several problems and introduces requested new features in
VOMS Admin server. The list of bug fixes is given in full below. Here the main
new features will be described

#### Java 8

VOMS Admin server now requires Java 8.

#### AUP signature reminders

It is now possible to configure VOMS Admin to send multiple reminders to remind
users of AUP signature requests.

The `voms.aup.sign_aup_task_lifetime` option in the `/etc/<vo>/service.properties` configuration
file now accepts a comma separated list of values as in:

    voms.aup.sign_aup_task_lifetime = 14,7,1

With the settings above, VOMS Admin would send three reminders to a user that is requested
to sign the AUP: 14,7 and 1 day before the grace period expiration.

#### Improved user requests handling

The handle user request home page has been redesigned to support multiple request handling
with a single click and improved readability.

#### VOMS Admin audit log

VOMS Admin now keeps an audit log in the database of all the relevant
management actions performed on the VOMS database by administrators and by the
system itself.

The audit log can be queried from the audit log page, which replaces the former
request log page.

#### VOMS links to CERN HR DB via the HR db user id field

VOMS now links membership to data in the CERN HR database using the user HR user id field (which
cannot be changed by users) instead of the user email addresses.

The HR id used for a given VOMS user can be changed by VO administrators. This change 
does not affect the current registration flow.

#### Authentication info page

VOMS Admin now has a page that can be used to display information about the
certificate used when connecting to the service. The page will tell:

- if the user is authenticated (i.e. has provided a valid and trusted certificate)
- if the user certificate grants administrator permissions for the VO
- if there's a VO membership linked to the certificate

#### Group manager role

It is now possible to leverage VOMS roles to group together group managers,
i.e. administrators that have the right to approve group membership requests
and role assignment requests that are specific for a VO group.

### Bug fixes

{% include list-rfcs.liquid %}

### New features and improvements

{% include list-features.liquid %}

### Installation and configuration

#### Upgrade from VOMS Admin Server >= 3.2.0

A [reconfiguration][reconf] and a [database upgrade][db-upgrade] are required
to upgrade to VOMS Admin Server 3.4.0.

#### Upgrade from earlier VOMS Admin Server versions

First upgrade to VOMS Admin version [3.2.0][voms-admin-320-rn] and then to 3.4.0.

#### Clean install

Follow the instructions in the VOMS [System Administrator Guide][sysadmin-guide].

[voms-website]: http://italiangrid.github.io/voms
[sysadmin-guide]:{{site.baseurl}}/documentation/sysadmin-guide/3.0.5
[sysadmin-guide-db-upgrade]:{{site.baseurl}}/documentation/sysadmin-guide/3.0.5/#db-upgrade
[voms-admin-guide]: {{site.baseurl}}/documentation/voms-admin-guide/3.4.0
[voms-admin-320-rn]: {{site.baseurl}}/release-notes/voms-admin-server/3.2.0
[reconf]: {{site.baseurl}}/documentation/sysadmin-guide/3.0.5/#reconf
[db-upgrade]: {{site.baseurl}}/documentation/sysadmin-guide/3.0.5/#db-upgrade
