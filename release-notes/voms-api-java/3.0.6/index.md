---
layout: default
title: VOMS API Java v. 3.0.6
rfcs:
    - id: VOMS-653
      title: VOMS Java APIs select SSLv3 for legacy VOMS requests
    - id: VOMS-703
      title: CertificateValidatorBuilder should allow to configure whether is running in an OpenSSL 1.x or 0.9.x envinroment
---

# VOMS API Java v. 3.0.6

This version of the Java APIs provide the following improvement and bug fixes:

- SSLv3 is no longer used for legacy VOMS requests

- The CertificateValidatorBuilder allows callers to select the hash function
  used to resolve trust anchors

### Bug fixes

{% include list-rfcs.liquid %}

### Installation

#### From Maven central

```xml
<dependency>
  <groupId>org.italiangrid</groupId>
  <artifactId>voms-api-java</artifactId>
  <version>3.0.6</version>
</dependency>
```

#### From RPM package

For a clean install:

```bash
yum install voms-api-java3
```

For an update install:

```bash
yum update
```
