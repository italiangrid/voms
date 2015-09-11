---
layout: default
title: VOMS Admin server v. 3.4.0 - Handle multiple requests via a single click
---

- [VOMS-633](https://issues.infn.it/jira/browse/VOMS-633) - Add ability to handle multiple requests page from VOMS Admin "Handle requests" page
- [VOMS-634](https://issues.infn.it/jira/browse/VOMS-634) - VOMS Admin handle request page should show only requests that can be handled by an administrator

#Handle multiple requests via a single click

From [VOMS Admin 3.4.0][vomsadmin340], administrators can handle multiple requests at once, from their home page. They can select the desired requests one by one, by checking each request at once, or all of them with a single click. 

{% include image.html url="images/multiple-selection-none.jpg" description="<b>Fig.1</b>: When no selection has been done, the approve/reject buttons are inline" %}

Administrators can still handle singularly a request. When the cursor is over a request, the inline approve/reject buttons will appear (fig.1). 

When one or multiple requests have been selected, using the checkboxes, the approve and reject button will appear only on the top (fig.2).

{% include image.html url="images/multiple-selection.jpg" description="<b>Fig.2</b>: One request selected via checkbox: the approve/reject buttons appear on top" %}

Using the checkbox on the top, administrators can select/deselect all the requests (fig.3).

{% include image.html url="images/multiple-selection-all.jpg" description="<b>Fig.3</b>: All the requests selected: the approve/reject buttons appear on top" %}

With a single click on the desired button, all the selected requests will be updated.

[vomsadmin340]: {{site.baseurl}}/release-notes/voms-admin-server/3.4.0/