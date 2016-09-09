---
layout: default
title: VOMS MySQL Plugin v. 3.1.7
rfcs:
  - id: VOMS-748
    title: VOMS MySQL plugin uses the wrong MySQL type for returning the user id
---
# VOMS MySQL plugin v. 3.1.7

This release provides a fix for an incorrect type used in some VOMS queries.

### Bug fixes

{% include list-rfcs.liquid %}

### Installation and configuration

A restart of the VOMS service is needed after the plugin package has been
installed.

For clean and update installation instructions, follow the instructions in the
[VOMS System Administrator
guide]({{site.baseurl}}/documentation/sysadmin-guide/3.0.6).
