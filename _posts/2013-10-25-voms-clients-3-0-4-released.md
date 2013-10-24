---
layout: post
title: VOMS clients v. 3.0.4 and VOMS Java APIs v. 3.0.2 
author: valerio
summary: VOMS Java APIs fixes a problem that broke interoperability with the dCache SRM clients
---

The VOMS Product Team is pleased to announce the release of VOMS clients v. 3.0.4 and VOMS Java APIs v. 3.0.2.

This release provides an important bug fix, as highlighted in the release notes
for the [clients][rel-notes-clients] and the [APIs][rel-notes-apis]. Packages
can be obtained from our repositories and will soon be available on the EMI-3
repository. Follow the instructions in the [download section][downloads].

The new packages provide fixes for the problems described in
[this ticket][dcache-incident]. 
The issue was that private keys embedded in VOMS proxies created by 
the new VOMS clients were encoded following the PKCS#8 standard instead
of the PKCS#1 formerly used by VOMS clients version 2.x.
While the PKCS#8 standard is correctly handled by most middleware components,
the old jglobus library used by dCache SRM clients does not understand it
 so the parsing of VOMS proxies resulted in a failure.

Another issue was found in [CANL][canl], on which Java APIs are based. CANL, when
serializing the VOMS proxies did not set the KeyUsage extension as critical,
and this caused failures when contacting services where the KeyUsage check
was implemented stricly. CANL 1.3.0 fixes this issue and VOMS Java APIs
were updated to explicitly depend on that version.

[canl]: https://github.com/eu-emi/canl-java
[rel-notes-clients]: {{site.baseurl}}/release-notes/voms-clients/3.0.4
[rel-notes-apis]: {{site.baseurl}}/release-notes/voms-api-java/3.0.2
[dcache-incident]: https://ggus.eu/ws/ticket_info.php?ticket=97555
[downloads]: {{site.baseurl}}/download.html
[voms-api-java]: https://github.com/italiangrid/voms-api-java
