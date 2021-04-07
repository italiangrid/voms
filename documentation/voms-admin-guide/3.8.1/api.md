---
layout: default
title: VOMS Admin REST API documentation
version: 3.8.1
---

# VOMS Admin REST API documentation

{% include voms-admin-guide-version.liquid %}

VOMS Admin provides a set of REST APIs that can be used to obtain information
about users. The APIs documented here provide **read-only** access to the information 
in the VOMS database.

#### Authentication and XSRF requirements

Calls to the API endpoints are authenticated via X.509 client certificates or
proxies and must include the (possibly empty) `X-VOMS-CSRF-GUARD` HTTP header.

The following CURL command shows an example call to the `/users` API endpoint,
which returns information about the users registered in a VO:

```console
curl -s -H "X-VOMS-CSRF-GUARD: y" \ 
  --capath /etc/grid-security/certificates/ --cert /tmp/x509up_u501 \ 
  https://voms.example.org:8443/voms/test_0/apiv2/users
```

will produce an output like:

```json
{
  "count": 1,
  "pageSize": 100,
  "result": [
    {
      "address": "an address",
      "attributes": [
        {
          "name": "nickname",
          "value": "a nickname"
        }
      ],
      "aupAcceptanceRecords": [
        {
          "aupVersion": "1.0",
          "daysBeforeExpiration": 364,
          "lastAcceptanceDate": "2017-08-10T11:56:12",
          "valid": true
        }
      ],
      "cernHrId": 374310,
      "certificates": [
        {
          "creationTime": "2017-08-10T11:56:12",
          "issuerString": "/C=IT/O=INFN/CN=INFN Certification Authority",
          "subjectString": "/C=IT/O=INFN/OU=Personal Certificate/L=CNAF/CN=Andrea Ceccanti",
          "suspended": false,
          "suspensionReason": null
        }
      ],
      "creationTime": "2017-08-10T11:56:12",
      "emailAddress": "andrea.ceccanti@example.org",
      "endTime": null,
      "fqans": [
        "/test_0"
      ],
      "id": 1,
      "institution": "CNAF - Italian National Center for Research and Development (CNAF)",
      "name": "ANDREA",
      "pendingSignAUPTask": null,
      "phoneNumber": null,
      "surname": "CECCANTI",
      "suspended": false,
      "suspensionReason": null,
      "suspensionReasonCode": null
    }
  ],
  "startIndex": 0
}
```

A detailed description of the APIs can be found [here][swagger].

[Back to VOMS Admin guide](index.html)

[swagger]: swagger/index.html
