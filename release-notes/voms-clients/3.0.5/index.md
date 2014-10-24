---
layout: default
title: VOMS Clients v. 3.0.5
rfcs:
    - id: VOMS-509
      title: VOMS clients do not honour VOMSES vo aliases
    - id: VOMS-460
      title: voms-proxy-init ignores -cert option when used with -noregen
    - id: VOMS-495
      title: Make voms-clients3 packages installable together with voms-clients
---

# VOMS Clients v. 3.0.5

This release provides bug fixes for the VOMS Java clients and introduces new
packaging of the clients that makes them installable together with native
clients (version  >= 2.0.12).

### Bug fixes

{% include list-rfcs.liquid %}

### Installation and configuration

For clean and update installation instructions, follow the instructions in the [VOMS clients guide]({{site.baseurl}}/documentation/voms-clients-guide/3.0.3).

### Known issues

None at the moment.
