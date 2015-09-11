---
layout: default
title: VOMS Admin server v. 3.4.0 - Authenticated users's detail page
---

[VOMS-654](https://issues.infn.it/jira/browse/VOMS-654) - VOMS should provide a page that displays detailed information about the certificate used to connect to the service

##Authenticated users's detail page

It is useful for users to know if they're connecting to VOMS Admin with a valid certificate, especially at registration time.
From [VOMS Admin 3.4.0][vomsadmin340], authenticated users can access a page that lists, in particular:

- if the user is authenticated (i.e. has provided a valid and trusted certificate)
- if she's granted VO administrator permission in the VO
- if there's a VO membership linked to her certificate

{% include image.html url="images/certificate-info.jpg" description="<b>Fig.1</b>: Personal certificate page example." %}

[vomsadmin340]: {{site.baseurl}}/release-notes/voms-admin-server/3.4.0/