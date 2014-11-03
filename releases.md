---
layout: default
title: VOMS releases
---

# VOMS releases

{% include releases.liquid %}

### Repository configuration

VOMS packages can be obtained from the EMI repository or from the VOMS product team package repository.

#### EMI 3

You can find [general EMI 3 installation instructions](https://twiki.cern.ch/twiki/bin/view/EMI/GenericInstallationConfigurationEMI3) on the EMI site, but it basically boils down to installing the EMI repository

    rpm --import http://emisoft.web.cern.ch/emisoft/dist/EMI/3/RPM-GPG-KEY-emi
    wget http://emisoft.web.cern.ch/emisoft/dist/EMI/3/sl5/x86_64/base/emi-release-3.0.0-2.el5.noarch.rpm
    yum localinstall -y emi-release-3.0.0-2.el5.noarch.rpm

Follow the [system administrator guide]({{site.baseurl}}/documentation/sysadmin-guide}}) for detailed installation instructions.

#### VOMS

Note that the VOMS PT repositories only provide the latest version of the certified VOMS packages.
You still need to install EMI3 repositories (as detailed above) for installations to work as expected.

To install the repository files, run the following commands (as root):

    (SL5) # wget http://italiangrid.github.io/voms/repo/voms_sl5.repo -O /etc/yum.repos.d/voms_sl5.repo
    (SL6) # wget http://italiangrid.github.io/voms/repo/voms_sl6.repo -O /etc/yum.repos.d/voms_sl6.repo

### Nightly builds

Development versions are built regularly on our [continuos integration infrastructure](http://radiohead.cnaf.infn.it:9999/view/VOMS/). 

Artifacts produced from the development branch can be found on our development yum repos for [SL5 x86/64][repo_develop_sl5] and [SL6 x86/64][repo_develop_sl6].

### Source code

The VOMS source is available on [Github](https://github.com) in the following repositories:

- [VOMS clients](https://github.com/italiangrid/voms-clients)
- [VOMS core](https://github.com/italiangrid/voms)
- [VOMS Admin server](https://github.com/italiangrid/voms-admin-server)
- [VOMS Admin client](https://github.com/italiangrid/voms-admin-client)
- [VOMS C/C++ APIs](https://github.com/italiangrid/voms)
- [VOMS Java APIs](https://github.com/italiangrid/voms-api-java)
- [VOMS mysql plugin](https://github.com/italiangrid/voms-mysql-plugin)
- [VOMS oracle plugin](https://github.com/italiangrid/voms-oracle-plugin)

[voms-emi3]: http://www.eu-emi.eu/releases/emi-3-montebianco/products/-/asset_publisher/5dKm/content/voms-2
[repo_develop_sl5]: http://italiangrid.github.io/voms/repo/voms_develop_sl5.repo
[repo_develop_sl6]: http://italiangrid.github.io/voms/repo/voms_develop_sl6.repo
