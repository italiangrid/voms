---
layout: default
title: VOMS API Java v. 3.0.1
rfcs:
    - id: VOMS-364
      title: VOMS Java APIs v. 3.0.0 serialize PEM fragments in proxy file in the wrong order
    - id: VOMS-352
      title: VOMS JAVA APIs are confused by HTTP connection errors
---

# VOMS API Java v. 3.0.1

This release fixes a regression introduced with version 3.0.0 of the VOMS Java APIs that
caused issues when uploading proxy certificates and getting delegations out of MyProxy servers.

A problem that caused failures in getting VOMS attribute certificates out of the BNL VOMS
server has also been fixed.

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
