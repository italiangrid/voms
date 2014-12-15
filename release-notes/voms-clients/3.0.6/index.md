---
layout: default
title: VOMS Clients v. 3.0.6
rfcs:
    - id: VOMS-566
      title: VOMS clients and Java APIs should provide a flag to disable host name verification
---

# VOMS Clients v. 3.0.6

This release provides a flag `--skip_hostname_checks` to turn off hostname
verification when contacting VOMS servers.

### Bug fixes

{% include list-rfcs.liquid %}

### Installation and configuration

For clean and update installation instructions, follow the instructions in the
[VOMS clients guide]({{site.baseurl}}/documentation/voms-clients-guide/3.0.3).

