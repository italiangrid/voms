---
layout: default
title: VOMS Releases
---

{% include releases.liquid %}

## Repository configuration

For RedHat derivatives, VOMS packages can be obtained from [UMD][umd], [EPEL][epel] or [our own][voms-repo] repositories. We suggest taking them from EPEL.

Note that if you take the packages from our own repository you still probably need to enable the UMD and/or EPEL repositories to get some dependencies.

Packages are available also for Debian.

Many thanks to Mattias Ellert for maintaining EPEL and Debian packages.

## Source code

The source code for all VOMS components is available on [GitHub](https://github.com) in the following repositories:

- [VOMS Java Clients](https://github.com/italiangrid/voms-clients)
- [VOMS Java APIs](https://github.com/italiangrid/voms-api-java)
- [VOMS Core (Server, C/C++ APIs and Clients)](https://github.com/italiangrid/voms)
- [VOMS MySQL Plugin](https://github.com/italiangrid/voms-mysql-plugin)
- [VOMS Admin Server](https://github.com/italiangrid/voms-admin-server)
- [VOMS Admin Client](https://github.com/italiangrid/voms-admin-client)

[umd]: https://repository.egi.eu/umd/index.html
[epel]: https://docs.fedoraproject.org/en-US/epel/
[voms-repo]: https://italiangrid.github.io/voms-repo/
