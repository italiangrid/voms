---
layout: default
title: VOMS Admin administrator's guide
version: 3.4.0
admin_server_version: 3.4.0
admin_client_version: 2.0.19
---

# VOMS Admin VO administrator guide

- Covering VOMS Admin server  {{ page.admin_server_version}}, VOMS Admin client  {{ page.admin_client_version}}

#### Table of contents

- [Introduction](#intro)
- [VOMS membership management](#membership-lifecycle)
- [Managing user requests](#managing-user-requests)
- [Managing groups](#managing-groups)
- [Managing roles](#managing-roles)
- [Managing Generic Attributes](#managing-attributes)
- [Managing user information](#managing-user-information)
- [Acceptable Usage Policies management](#aup-management)
- [The Audit Log](#audit-log)

## Introduction <a name="intro"></a>

In VOMS, a Virtual Organisation (VO) is a named container for a set of VO
members organized in groups. As an example, the `atlas` VO at CERN has 3000
registered users and 70 groups.

VOs are managed by one or more VO administrators, i.e. privileged users
that are responsible for defining the VO structure (groups, roles, attribute
classes), approve user requests and perform other administrative tasks.

This guide is targeted at VO administrators. It introduces the main
VOMS administration concepts and functions.

## VOMS membership management <a name="membership-management"></a>

TBD

### Managing user request <a name="managing-user-requests"></a>

VO administrators are responsible of managing user requests. User requests
can be of the following types:

- VO membership requests, i.e., VO registration requests
- Group membership requests, i.e., requests issued to be added to a VO group
- Role assignment requests, i.e., requests issued to be assigned a given VOMS role
- Certificate requests, i.e., requests to add an additional certificate to a given VOMS membership
- Membership removal requests, i.e. requests to be removed from the VO

All pending requests are shown in the VO administrator home page, shown below:

<img src="img/home-requests.png" class="img-polaroid">

When moving the mouse pointer over a request, the approve and reject buttons
appear to approve/reject each request.

It is also possible to approve/reject multiple requests with a single click, by
selecting them and then approve/reject them with the buttons in the upper right
corner of the request table:

<img src="img/home-requests-2.png" class="img-polaroid">

### Managing groups <a name="managing-groups"></a>

VO groups can be created and deleted from the "Groups" management page, that can be 
reached by clicking the "Browse groups" link in the VOMS admin browse navbar:

<img src="img/groups.png" class="img-polaroid">

#### The Group information page <a name="group-info-page"></a>

Clicking on the group name in the "Browse groups" page leads to the "Group
information" page, where information about description, membership and
attributes defined at the group level can be accessed.

<img src="img/group-detail.png" class="img-polaroid">

- For more information regarding ACLs and VOMS Admin authorization, see .
- For more information regarding Generic Attributes management, see [Managing
  attributes](#managing-attributes).

### Managing roles <a name="managing-roles"></a>

VO roles can be created and deleted from the "Roles" management page, that can be
reached by clicking the "Browse roles" link in the VOMS Admin browse navbar:

<img src="img/roles.png" class="img-polaroid">

#### The Role information page <a name="role-info-page"></a>

Clicking on the role name in the "Browse roles" page leads to the "Role
information" page, where information about role membership and attributes
defined at the role level can be accessed.

<img src="img/role-detail.png" class="img-polaroid">

- For more information regarding ACLs and VOMS Admin authorization, see .
- For more information regarding Generic Attributes management, see .

### Managing Generic Attributes <a name="managing-attributes"></a>

Generic attributes (GAs) are (name, value) pairs that that can be assigned to
VO users. This information will then be encoded in the VOMS Attribute Certificate
issued by the VOMS server as a result for a voms-proxy-init request. 

GAs extend the range of attributes that VOMS can issue besides Fully Qualified
Attributes Names (FQAN), which is a fancy name for VOMS groups and roles, to
allow VOMS to issue any kind of VO membership information that can be expressed
as (name, value) pairs. Such information can then be leveraged by VOMS-aware
applications to take authorization decisions.

For their nature, GAs are issued to VO users. VOMS however provides a way to
quickly assign GAs to all the VO members that belong to a specific VOMS group
or that are assigned a specific VOMS role within a group. For this reason, you
find GA management in user, group and role management pages in VOMS Admin.

To assign GA to users, the VO admin must first create the corresponding
**Attribute Class**. The Attribute Class is used to define:

- the name of the attribute
- a description for the attribute class
- whether VOMS Admin should also enforce value uniqueness, so that the same
GA value cannot be assigned to distinct VO members.

#### Attribute class management

The "Attribute classes" management page can be reached by clicking on the “Attributes”
link in the navbar, and then clicking on the “Manage attribute classes” link.

<img src="img/attribute-classes.png" class="img-polaroid">

GA classes can then be created, specifying the GA name, description and whether
uniqueness must be enforced on the GA values assigned directly to users. 

<img src="img/attribute-class-management.png" class="img-polaroid">

#### Assigning generic attribute to users, groups and roles

Once a GA class has been created, GA values can be assigned to users, groups
and role within groups.

As mentioned above, when one GA is assigned directly to a user, the
(name,value) couple is added by VOMS to the attribute certificate returned to
user. GAs are assigned to users from the "Generic Attributes" panel in the
[User information page](#user-info-page).

When a GA is assigned to a group, or role within a group, such (name, value)
pair ends up in the Attribute Certificate of all the VO members belonging to
that group (or that have such role within a group). GAs are assigned to groups
and roles from the "Generic Attributes" panel in the [Group
information](#group-info-page) or [Role information](#role-info-page) pages.

#### Search attribute assigned to users

VOMS Admin implements search over user generic attribute values assigned to
users, from the "Browse Attributes" page.

<img src="img/attribute-search.png" class="img-polaroid">

### Managing user information <a name="managing-user-information"></a>

#### The Browse users page <a name="browse-users-page"></a>

The **Browse users** page provides the following functionality:

- Search users, with filters to limit the matches to suspended users or users
  that are requested to sign the AUP
- Suspend/restore multiple users
- Delete multiple users
- Extend membership for some users
- Access the user information page for a given user

The screenshot below shows the "Browse users" page for a WLCG VO:

<img src="img/browse-users-page.png" class="img-polaroid">

#### The user information page <a name="user-info-page"></a>

The "User Information" page gives detailed information about a VO member and
provides the administration functionalities to:

- suspend/restore the VO member
- manage the VO member personal information
- assign the member to groups and roles
- manage the VO member certificates
- show information about AUP signatures
- request AUP signature from the user
- sign the AUP on behalf of the user
- change the CERN HR id for the user (only applicable for CERN WLCG VOs)

To reach the user information page for a given VO member, click the "more info" link
for a given member from the "Browse users" page, as shown below:


#### Suspending a VO member

Suspended members are legitimate members of of the VO, but cannot obtain VOMS
attribute certificates from the VOMS server.

To suspend a single user, go to the [User information page](#user-info-page) and click
the "Suspend this user" button.

<img src="img/suspend-user.png" class="img-polaroid">

The [Browse users page](#browse-users-page) provides a way to suspend multiple users with
a single click.

#### Manage the VO member personal information

The VO admin can change personal information linked to a VO membership through
the "Personal information" panel in the [User information page](#user-info-page).

<img src="img/personal-info-management.png" class="img-polaroid">

For WLCG VOs some fields cannot be changed as the member personal information
is synchronized with the contents of the CERN Human Resource database.

#### Assign the VO member to groups and roles

The "Groups and roles" panel in the [User information page](#user-info-page) provides
the ability to add the VO member to VO groups and assign him VO roles.

<img src="img/groups-and-roles.png" class="img-polaroid">

#### Manage the VO member certificates

The "Certificates" panel in the [User information page](#user-info-page) provides
the following functionality:

- add an additional certificate linked to the VO membership
- remove a certificate linked to the VO membership (if more than one are listed)
- suspend a certificate linked to the VO membership

<img src="img/certificate-management.png" class="img-polaroid">

#### Show information about AUP signatures

The "AUP acceptance status" panel in the [User information page](#user-info-page) provides
the following functionality:

- shows when the AUP was last signed by the user, and when the signature will
  expire
- provides the ability to request a new AUP signature from the user, with the
  "Request AUP reacceptance" button

<img src="img/aup-signature-management.png" class="img-polaroid">

The "Sign AUP on behalf of the user" button at the top of the [User information
page](#user-info-page) allows a VO admin to sign the AUP on behalf of a user.

<img src="img/sign-aup-on-behalf.png" class="img-polaroid">

#### Change the CERN HR id for the user (WLCG CERN VOs only)

The "Change HR id" button, at the top of the [User information
page](#user-info-page), allows to change the CERN Human Resource identifier
linked to a VOMS membership.

<img src="img/change-hr-id.png" class="img-polaroid">

The HR id entered will be validated by VOMS to check if a valid membership for
the experiment linked to such id and the currently managed VO is found in the
HR database. 
If the check succeeds, the membership information will be synchronized with the
content of the HR membership record at the next run of the VOMS HR database
synchronization task.

### Acceptable usage policy (AUP) management

VOMS Admin implements AUP management, to keep track of when users accepted a
certain version of the AUP configured for a VO. To do this, VOMS Admin
maintains an **acceptance record** for each user, that keeps track of which
version of the AUP was signed by the user and when.

The AUP in VOMS Admin has a reacceptance period. For example, by default the VO
AUP must be signed every 12 months by each VO user. To enforce this constraint,
VOMS admin checks each user's acceptance record against the currently valid AUP
reacceptance period. If the user AUP signature has expired, the user is
notified by email and asked to sign again the AUP. 

The user has typically two weeks time to sign the AUP after his signature has
expired (the grace period duration is configurable). If the user fails to sign
the AUP during this grace period, he is automatically suspened by VOMS Admin.

The membership suspension holds only until the user sign the AUP following the
instructions send to him by email, or a VO admin signs the AUP on behalf of the
user.

**Important**: no intervention is requested from the VO admin to restore
the user membership in normal situations, as the user can restore his membership
at any time by just signing the AUP as requested.

The user acceptance record can also be invalidated by a VO administrator at any time
to request a new signature from the user.

#### The AUP management page

The AUP management page can be reached from the "Browse AUP" link in the browse navbar
and provides the following functionality:

- Show the currently active AUP text
- Change the AUP reacceptance period (in days)
- Add a new AUP version
- Delete an AUP version that is not marked as active
- Set the active AUP version
- Trigger reacceptance for the active AUP version

<img src="img/aup-management-page.png" class="img-polaroid">

##### Change the AUP reacceptance period
