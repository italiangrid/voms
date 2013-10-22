---
layout: default
title: VOMS API Java v. 3.0.2
rfcs:
    - id: VOMS-424
      title: Serializing private key using pkcs#8 encoding confuses dCache clients
    - id: VOMS-378
      title: Migrate Java API to CAnL 1.3
---

# VOMS API Java v. 3.0.1

This release reverts to PKCS#1 as default encoding for serializing private keys
in VOMS proxies. The dependency to CAnL is updated to version 1.3.0.
This CAnL version correctly marks [KeyUsage extension as critical][canl-issue].

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

[canl-issue]: https://github.com/eu-emi/canl-java/issues/59
