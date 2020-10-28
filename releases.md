---
layout: default
title: VOMS releases
---

# VOMS releases

{% include releases.liquid %}

### Repository configuration

VOMS packages can be obtained from the UMD repository or from the VOMS product team package repository.

#### UMD repository

You can find UMD repository configuration instructions [here][umd].
Follow the [system administrator
guide]({{site.baseurl}}/documentation/sysadmin-guide) for detailed VOMS
installation instructions.

#### VOMS repository

The [VOMS package repository][voms-repo] provides packages for CENTOS 6/7.

Note that the VOMS PT repositories only provide the latest version of the certified VOMS packages.
You still need to install UMD repositories (as detailed above) for installations to work as expected.

### Source code

The VOMS source is available on [Github](https://github.com) in the following repositories:

- [VOMS clients](https://github.com/italiangrid/voms-clients)
- [VOMS core](https://github.com/italiangrid/voms)
- [VOMS Admin server](https://github.com/italiangrid/voms-admin-server)
- [VOMS Admin client](https://github.com/italiangrid/voms-admin-client)
- [VOMS C/C++ APIs](https://github.com/italiangrid/voms)
- [VOMS Java APIs](https://github.com/italiangrid/voms-api-java)
- [VOMS mysql plugin](https://github.com/italiangrid/voms-mysql-plugin)

[umd]: http://repository.egi.eu/category/umd_releases/distribution/umd-4/
[voms-repo]: https://italiangrid.github.io/voms-repo/
