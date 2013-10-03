---
layout: default
title: VOMS API Java v. 3.0.2
rfcs:
    - id: VOMS-378
      title: Migrate Java API to CAnL 1.3
---

# VOMS API Java v. 3.0.1

This release upgrade the dependency on CAnL to version 1.3. With this CAnL version, unlike the previous versions, when creating a proxy the KeyUSage extension is marked as critical. Not setting KeyUSage to critical caused the problems described [here][https://ggus.eu/ws/ticket_info.php?ticket=97555].

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
