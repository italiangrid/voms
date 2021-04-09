---
layout: default
title: VOMS Admin server v. 3.8.1
rfcs:
- id: VOMS-883
  title: HR db sync task is not started even when the `membership_check.enabled=true` property is set
- id: VOMS-887
  title: Update struts dependency to 2.5.26
---
# VOMS Admin server v. 3.8.1

### Bug fixes and enhancements

{% include list-rfcs.liquid %}

### Installation and configuration

A service restart is required for changes to take effect.

#### Clean install

Follow the instructions in the VOMS [System Administrator Guide][sysadmin-guide].

[sysadmin-guide]:{{site.baseurl}}/documentation/sysadmin-guide/3.0.14
