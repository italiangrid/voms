---
layout: default
version: 3.0.13
title: VOMS repositories
---

# VOMS repository configuration

{% include sysadmin-guide-version.liquid %}


VOMS requires the following repositories enabled:

- EPEL 
- UMD 
- X.509 CA certificates (aka trust anchors)

## EPEL
To install the EPEL repository use the following command:

```
yum -y install epel-release
```

## UMD 

To install the UMD repository, follow the instructions [on the UMD web
site][umd].

## Trust anchors

To work as expected, VOMS requires the IGTF trust anchors installed. In Europe,
this is done by installing packages from the [EGI trust anchors
repository][egi-trustanchors].

## VOMS repositories

TBD

[voms-conf-ref]: {{site.baseurl}}/documentation/sysadmin-guide/{{page.version}}/configuration.html
[egi-trustanchors]: https://wiki.egi.eu/wiki/EGI_IGTF_Release
[umd]: https://repository.egi.eu/category/umd_releases/distribution/umd-4/
