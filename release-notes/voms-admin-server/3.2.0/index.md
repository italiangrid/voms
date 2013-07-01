---
layout: default
title: VOMS Admin server v. 3.2.0

rfcs: 
    - id: VOMS-260
      title: VOMS Admin cannot handle certificate request for certificates with different CAs and the same subject
    - id: VOMS-259
      title: EMI-3 VOMS-Admin does not publish GLUE2EndpointStartTime
    - id: VOMS-257
      title: VOMS Admin should keep in database the date of last membership expiration warning notification sent

features:
    - id: VOMS-266
      title: Hierarchical notification dispatching in VOMS Admin
    - id: VOMS-351
      title: Request log visible on VOMS Admin webapplication
---

# VOMS Admin server v. 3.2.0

This release provides several bug fixes and improvements for VOMS Admin server.
In particular:

- VOMS Admin now support **Group managers**, a mechanism which allow the hierarchical dispatching
of the notification resulting from user VO membership and group membership requests.

- A **Request log** section has been added to the VOMS Admin web application. The log shows information
about requests handled (approval time, who approved the request etc.)


### Bug fixes

{% include list-rfcs.liquid %}

### New features

{% include list-features.liquid %}

### Installation and configuration

This release requires a reconfiguration and the upgrade of the VOMS database. Follow the instructions in the
VOMS [System Administrator Guide]({{site.baseurl}}/documentation/sysadmin-guide).

### Known issues

None at the moment

[voms-website]: http://italiangrid.github.io/voms
