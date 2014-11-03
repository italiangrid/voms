---
layout: default
title: VOMS Clients v. 2.0.12-2
rfcs:
    - id: VOMS-543
      title: VOMS spec file does not set build dependency on gSoap devel
---

# VOMS Clients v. 2.0.12-2

This release fixes an issue in the VOMS packaging that caused build failures
with mock by adding a build-time dependency on gSoap-devel that was
previously missing.

No change in functionality comes with this voms clients release.

### Bug fixes

{% include list-rfcs.liquid %}
