---
layout: default
title: VOMS API Java v. 3.0.5
rfcs:
    - id: VOMS-568
      title: Hostname check failures are not handled correctly
    - id: VOMS-567
      title: VOMS Java APIs should select VOMS endpoint only by alias
    - id: VOMS-566
      title: VOMS clients and Java APIs should provide a flag to disable host name verification
---

# VOMS API Java v. 3.0.5

This version of the Java APIs provide the following improvement and bug fixes:

- it is now possible to disable hostname verification checks

- the vomses files are now looked up only by alias. The lookup behaviour
  implemented in v.3.0.4 was not backward-compatible with former implementations

- Hostname check failures are now handled correctly, i.e. an hostname check failure
  does not break the loop over available server endpoints for a given VO

### Bug fixes

{% include list-rfcs.liquid %}

### Installation and configuration

For a clean install:

```bash
yum install voms-api-java3
```

For an update install:

```bash
yum update
```
