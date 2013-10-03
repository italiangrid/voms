---
layout: default
title: VOMS Clients v. 3.0.4
rfcs:
    - id: VOMS-424
      title: Serializing private key using pkcs#8 encoding confuses dCache clients
    - id: VOMS-423
      title: More informative description of -hours in voms-proxy-init man page (and help message). 
---

# VOMS Clients v. 3.0.4

This release fixes a regression introduced with version 3.0.0 of the clients in
the `voms-proxy-init` command. This release also contains an improvement of the 
`voms-proxy-init` man page.

### Bug fixes

{% include list-rfcs.liquid %}

### Installation and configuration

For clean and update installation instructions, follow the instructions in the [VOMS clients guide]({{site.baseurl}}/documentation/voms-clients-guide).

### Known issues

None at the moment.
