---
layout: post
title: VOMS clients v. 3.0.3 and VOMS Java APIs v. 3.0.1 
author: andrea
summary: The new VOMS clients release provides several bug fixes
---

The VOMS Product Team is pleased to announce the release of VOMS clients v. 3.0.3 and VOMS Java APIs v. 3.0.1.

This release provide several bug fixes, as highlighted in the release notes
for the [clients][rel-notes-clients] and the [APIs][rel-notes-apis]. Packages
can be obtained from our repositories and will soon be available on the EMI-3
repository. Follow the instructions in the [download section][downloads].

As you may already know by now, version 3 of the clients are a full rewrite
based on the [VOMS Java APIs 3.x][voms-java-api] which are in turn based on
[CAnL][canl]. The main advantages of the new clients are:

- a [code base][voms-clients-code] that is much easier to maintain and evolve
- improved error messages and debugging 
- full SHA-2 compliance

In order to avoid regressions as much as we could we introduced a
[testsuite][voms-testsuite] based on the [Robot framework][robot]. Each time a
new issue is found or new functionality is added, new tests are added to
verify the correct behaviour of the clients.

One of the problems solved with this release was spotted by [this incident][myproxy-incident],
which showed that VOMS clients version 3.0.x broke the WLCG VO box. In particular, it was no
longer possible to renew a credential stored in a MyProxy server. This issue was caused by the wrong order
in which PEM fragments were serialized to file when storing a VOMS proxy, and was
quite easy to [fix][myproxy-fix]. [Tests][myproxy-tests] were also added to the testsuite to continuosly
verify that the clients work as expected with MyProxy.

There are times however when it is not possible or convenient to add a test for a given regression. 
This [incident][memory-issue] showed a strange behaviour of the clients which was observed only in setups with
very large amounts of RAM (128G). When the Java VM is started without specifiying explicitly heap memory 
limits, java reclaims a given fraction of the available memory for its process. 
On WLCG worker nodes, that can be equipped with lots of RAM (> 128G), the memory reclaimed by the Java
VM hit the shell limit set for the maximum amount of virtual memory that a process can reclaim, 
and the clients failed to start. Actually, even

```bash
java --version
```
would have failed in such environment. The solution for this was to explicitly constrain the memory
requested by the clients in the clients startup script to a more sensible value (i.e. 16mb).


[canl]: https://github.com/eu-emi/canl-java
[rel-notes-clients]: {{site.baseurl}}/release-notes/voms-clients/3.0.3
[rel-notes-apis]: {{site.baseurl}}/release-notes/voms-api-java/3.0.1
[robot]: https://code.google.com/p/robotframework/
[memory-issue]: https://ggus.eu/ws/ticket_info.php?ticket=95574
[voms-testsuite]: https://github.com/italiangrid/voms-testsuite
[voms-java-api]: https://github.com/italiangrid/voms-api-java
[voms-clients-code]: https://github.com/italiangrid/voms-clients
[myproxy-incident]: https://ggus.eu/ws/ticket_info.php?ticket=95798
[myproxy-fix]: https://github.com/italiangrid/voms-api-java/commit/861da185133f6548412df0c8e8720ad8861d8ff0
[myproxy-tests]: https://github.com/italiangrid/voms-testsuite/blob/master/basic-tests/myproxy-tests.txt
[jenkins]: http://radiohead.cnaf.infn.it:9999/view/VOMS
[downloads]: {{site.baseurl}}/download.html
