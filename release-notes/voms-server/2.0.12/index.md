---
layout: default
title: VOMS Server v. 2.0.12
rfcs:
    - id: VOMS-507
      title: VOMS server embeds gSoap (while it should take it from the OS)
    - id: VOMS-459
      title: VOMS getId routine may cause segfault do to incorrect buffer handling
    - id: VOMS-456
      title: VOMS daemon does not update number of active requests until it reaches maximum
    - id: VOMS-444
      title: VOMS server disables core file dumping
    - id: VOMS-322
      title: Process forked by voms server crashes with empty voms requests
    - id: VOMS-135
      title: VOMS should have more stringent checks on incoming AC lifetime parameter
---

# VOMS Server v. 2.0.12

This release fixes several problems:

* gSoap is now taken from the OS (before it was embedded in the VOMS source code and
this could lead to issues)
* a routine that coused segfaults when DNS resolution resulted in errors has been removed
* VOMS does not disable core file dumping anymore
* More stringent validation have been implemented on incoming requests
* VOMS now correctly limits the number of incoming requests

### Bug fixes

{% include list-rfcs.liquid %}

### Installation and configuration

For clean and update installation instructions, follow the instructions in the [VOMS System Administrator guide]({{site.baseurl}}/documentation/sysadmin-guide/3.0.0).

### Known issues

None at the moment.
