---
layout: default
title: VOMS releases
---

# VOMS releases

{% include releases.liquid %}

### Repository configuration

VOMS packages can be obtained from the UMD repository or from the VOMS product team package repository.

#### UMD 3

You can find UMD 3 repository configuration instructions [here][umd-3].
Follow the [system administrator
guide]({{site.baseurl}}/documentation/sysadmin-guide) for detailed VOMS
installation instructions.

#### VOMS

Note that the VOMS PT repositories only provide the latest version of the certified VOMS packages.
You still need to install UMD3 repositories (as detailed above) for installations to work as expected.

To install the repository files, run the following commands (as root):

    # wget http://italiangrid.github.io/voms/repo/voms_sl6.repo -O /etc/yum.repos.d/voms_sl6.repo

### Nightly builds

Development versions are built regularly on our [continuos integration infrastructure][ci]. 

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


[ci]:  https://ci.cloud.cnaf.infn.it/view/voms/ 
[umd-3]: http://repository.egi.eu/category/umd_releases/distribution/umd-3/
[voms-emi3]: http://www.eu-emi.eu/releases/emi-3-montebianco/products/-/asset_publisher/5dKm/content/voms-2
