---
layout: default
title: VOMS Admin server v. 3.4.0 - Group-Manager role to grant group membership request rights
---

[VOMS-655](https://issues.infn.it/jira/browse/VOMS-655) - Group-Manager role to grant group membership request rights

##Group-Manager role

In most deployment scenario, VO administrators are members of the VO. VO administrators take care of all the membership requests. This new feature allows administrator users to delegate the handling of group requests (group membership requests, role assignment requests) scoped to a specific group to some VO users. This can be done by assigning to these VO users a particular VOMS role. The role name is configurable, with a sensible default ("Group-Manager").

Users with the "Group-Manager" role in the VO root group and in a given subgroup for which they are managers will receive notifications of incoming group membership requests and will have the rights to approve or reject these requests.

##Add a Group-Manager

If no group managers have been defined, the `Group managers` page will appear as follow: 

{% include image.html url="images/groupmanager-empty.jpg" description="<b>Fig.1</b>: No group manager role defined." %}

After clicking on `create one`, the information requested will be the followings:

{% include image.html url="images/groupmanager-create.jpg" description="<b>Fig.2</b>: Data required to create a group manager role for a particular group." %}

- Name
- Description
- e-mail
- VO's group

Press 'Create Group Manager' button to create the group manager. 