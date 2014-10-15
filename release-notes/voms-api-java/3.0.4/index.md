---
layout: default
title: VOMS API Java v. 3.0.4
rfcs:
    - id: VOMS-529
      title: VOMS Java APIs should allow 600 perms on certificate private key
    - id: VOMS-509
      title: VOMS clients do not honour VOMSES vo aliases
    - id: VOMS-504
      title: VOMS Java APIs should handle empty VOMS certificate and LSC store gracefully
    - id: VOMS-503
      title: LSC file parser should fail for files containing an odd number of dn entries
    - id: VOMS-455
      title: VOMS Java APIs should randomize the selection of the voms server endpoint
---

# VOMS API Java v. 3.0.4

This release provides several bugfixes.

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

### Known issues

None at the moment.
