---
layout: default
title: VOMS Server v. 2.0.11
rfcs:
    - id: VOMS-379
      title: Socket timeout can lead to VOMS Server hanging in endless loop
---

# VOMS Server v. 2.0.11

This release fixes a problem in the socket timeout handling that could lead
to an endless loop in the serving process when dealing with very slow clients. 

### Bug fixes

{% include list-rfcs.liquid %}

### Installation and configuration

For clean and update installation instructions, follow the instructions in the [VOMS System Administrator guide]({{site.baseurl}}/documentation/sysadmin-guide).

### Known issues

None at the moment.
