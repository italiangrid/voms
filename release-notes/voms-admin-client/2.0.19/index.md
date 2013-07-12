---
layout: default
title: VOMS Admin client v. 2.0.19
rfcs:
    - id: VOMS-144
      title: VOMS Admin CLI should print which certificate is used when the verbose option is set
---

# VOMS Admin client v. 2.0.19 

This release provides the following bug fixes.

### Bug fixes

{% include list-rfcs.liquid %}

### Installation and configuration

No configuration changes. Just run `yum update` to get
the latest package from the repository.

```bash
yum update voms-admin-client 
```

For clean installations, follow the instructions in the VOMS [System Administrator Guide]({{site.baseurl}}/documentation/sysadmin-guide).

### Known issues

None at the moment
