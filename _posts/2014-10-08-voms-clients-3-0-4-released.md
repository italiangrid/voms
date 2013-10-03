---
layout: post
title: VOMS clients v. 3.0.4 and VOMS Java APIs v. 3.0.2 
author: valerio
summary: The new VOMS clients release provides a fix for a problem that broke the dcache SRM client
---

The VOMS Product Team is pleased to announce the release of VOMS clients v. 3.0.4 and VOMS Java APIs v. 3.0.2.

This release provide an important bug fix, as highlighted in the release notes
for the [clients][rel-notes-clients] and the [APIs][rel-notes-apis]. Packages
can be obtained from our repositories and will soon be available on the EMI-3
repository. Follow the instructions in the [download section][downloads].

The versions fixes two problems that were causes of [this incident][dcache-incident]. The private keys for proxies created by version 3.0.3 of voms-proxy-init were encoded using PKCS#8 instead of PKCS#1, which were used by voms-proxy-init version 2.x. Though PKCS#8 is newer and a better choice, the jglobus library which is used by the dCache client do not understand it, and authentication to SRM services failed. Another problem was that voms-proxy-init did not set the KeyUsage extension as critical. This is actually done by [CAnL][canl], and the problem was fixed there and the [VOMS Java APIs][voms-api-java] updated to depends on the latest version. 

[canl]: https://github.com/eu-emi/canl-java
[rel-notes-clients]: {{site.baseurl}}/release-notes/voms-clients/3.0.4
[rel-notes-apis]: {{site.baseurl}}/release-notes/voms-api-java/3.0.2
[dcache-incident]: https://ggus.eu/ws/ticket_info.php?ticket=97555
[downloads]: {{site.baseurl}}/download.html
[voms-api-java]: https://github.com/italiangrid/voms-api-java
