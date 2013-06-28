---
layout: default
title: VOMS Admin server v. 3.2.0

rfcs: 
    - id: VOMS-266
      title: Hierarchical notification dispatching in VOMS Admin
    - id: VOMS-260
      title: VOMS Admin cannot handle certificate request for certificates with different CAs and the same subject
    - id: VOMS-259
      title: EMI-3 VOMS-Admin does not publish GLUE2EndpointStartTime
    - id: VOMS-257
      title: VOMS Admin should keep in database the date of last membership expiration warning notification sent
---

# VOMS Admin server v. 3.2.0

This release provides the following bug fixes and improvements for VOMS Admin server.

### Bug fixes

{% include list-rfcs.liquid %}

### Other news

* The VOMS web site and documentation is now hosted on [Github][voms-website].

### Installation and configuration

This release requires a reconfiguration of the VOMS Admin server. Follow the instructions in the
VOMS [System Administrator Guide][sysadmin.html].

### Known issues

None at the moment

[voms-website]: http://italiangrid.github.io/voms
