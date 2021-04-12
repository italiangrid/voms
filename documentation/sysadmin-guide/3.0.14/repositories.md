---
layout: default
version: 3.0.14
title: VOMS repositories
---

# VOMS repository configuration

{% include sysadmin-guide-version.liquid %}

VOMS is currently supported on the following platforms:

- CENTOS 7

VOMS requires the following repositories enabled:

- EPEL 
- UMD 
- X.509 CA certificates (aka trust anchors)
- VOMS repositories

Installation instructions for each repository are given in the following
sections.

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

In order to install VOMS you can use the VOMS PT package repositories, as
described in the [VOMS website release section][voms-releases].

For a working CENTOS 7 installation, install the
[stable](https://italiangrid.github.io/voms-repo/repofiles/rhel/voms-stable-el7.repo)
package repository and the [VOMS
externals](https://italiangrid.github.io/voms-repo/repofiles/rhel/voms-externals-el7.repo)
repo.


[voms-conf-ref]: {{site.baseurl}}/documentation/sysadmin-guide/{{page.version}}/configuration.html
[egi-trustanchors]: https://wiki.egi.eu/wiki/EGI_IGTF_Release
[umd]: https://repository.egi.eu/category/umd_releases/distribution/umd-4/
[voms-repositories]: https://italiangrid.github.io/voms-repo/
[voms-releases]: {{site.baseurl}}/releases.html
