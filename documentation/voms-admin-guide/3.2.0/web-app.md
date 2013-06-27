---
layout: default
title: The VOMS Admin web app
version: 3.2.0
---

## The VOMS Admin web application<a name="WebApplication">&nbsp;</a>

The VOMS-Admin web application provides a usable and intuitive interface towards VO management tasks. A screenshot of the main page of the web application is given above.

![Alt text](https://wiki.italiangrid.it/twiki/pub/VOMS/VOMSAdminUserGuide/webui1.png)

In the top part of the page, the header provides information about the current user accessing the interface and the name of the VO that is being managed. The two navigations bars provide access to the main sections of the web application.

### The Home page

By clicking on the home link in the main navbar one can reach his home page.

If the current client has administrator rights, she will be directed to the admins home page. User requests for membership and group/role assignments can be managed from this page, as shown in the image below.

![Alt text](https://wiki.italiangrid.it/twiki/pub/VOMS/VOMSAdminUserGuide/admin-home.png)

An administrator that is also a VO user will have a link to his user home page in the upper right part of the page.

If the current client has not admin rights, the VO user home page shows information about the user membership. From this page, the user can request group membership and role assignment and update his personal information. The page also shows information about AUP acceptance records and an history record of user's requests.

![Alt text](https://wiki.italiangrid.it/twiki/pub/VOMS/VOMSAdminUserGuide/user-home.png)

VO members can request the addition of a new certificate to their membership by clicking on the "Request new certificate" button in the Certificates panel, as shown in the picture below:

![Alt text](https://wiki.italiangrid.it/twiki/pub/VOMS/VOMSAdminUserGuide/user-request-cert-2.png)

The member can upload a PEM encoded certificate or type its certificate subject and select the CA subject from the certificate request page, pictured below:

![](https://wiki.italiangrid.it/twiki/pub/VOMS/VOMSAdminUserGuide/request-cert-page.png)

The certificate subject should be entered following the usual /-separated openssl rendering, like in:

/C=IT/O=INFN/OU=Personal Certificate/L=CNAF/CN=Andrea Ceccanti
After this step a notification is sent to the VO admin who has to approve the member's request. The user will be informed via email of the VO admin decision on the request.

### Managing users

The user management section of the VOMS-Admin web interface allows administrators to manage all the information regarding VO membership, i.e.:

- membership status
- registered certificates
- groups membership and role assignment
- generic attributes assignment
- AUP acceptance status

#### Suspended users

Since VOMS Admin 2.5, VOMS implements a user suspension mechanism.
Suspended users are legitimate members of of the VO, but cannot obtain VOMS attribute certificates from the VOMS server.

When suspending a user a reason for the suspension must be provided by the administrator. This reason will be included in a supension notification that will be sent to the user, and shown at `voms-proxy-init` time to suspended users that attempt to get a VOMS proxy.

### ACL Management

The ACL link the navigation bar leads to the ACL management page. The ACL management pane displays ACL entries in the form of (Voms Administrator, Set of permissions) couples. The display uses the compact representation for VOMS permissions that has been already introduced earlier.

![](https://wiki.italiangrid.it/twiki/pub/VOMS/VOMSAdminUserGuide/acl-management.png)

ACL entries can be added to ACL or default ACLs by clicking on the “add entry” link. Permissions can be set for:

* VO users;
* non VO users;
* Anyone having a specific role within a specific group;
* Anyone belongin to a specific VO group;
* Any authenticated user, i.e., everyone with a certificate issued by a trusted CA

Entries added to a group ACL can be propagated to existing context's ACLs by ticking the “Propagate to children context” tick box at the bottom of the page. Similarly, when editing or deleting an ACL entry from a group ACL, it is possible to propagate the deletion or editing to children groups by selecting the “Propagate to children context" tick box.

![](https://wiki.italiangrid.it/twiki/pub/VOMS/VOMSAdminUserGuide/add-ace.png)

### Managing VOMS generic attributes

Generic attributes (GAs) are (name, value) pairs that that can be assigned to VO users and that end up in the Attribute Certificate issued by VOMS. GAs extend the range of attributes that VOMS can issue besides Fully Qualified Attributes Names (FQAN), i.e., allow VOMS to issue any kind of VO membership information that can be expressed as (name, value) pairs. Such information can then be leveraged by Grid applications to take authorization decisions.

For their nature, GAs are issued to VO users. VOMS however provides a way to quickly assign GAs to all the VO members that belong to a specific VOMS group or that are assigned a specific VOMS role within a group. For this reason, you find GA management in user, group and role management pages in VOMS Admin.

To assign GA to users, the VO admin must first create the corresponding Generic Attribute class. This Generic Attribute class is used to define the name and possibly a description for the GA. VOMS Admin also implements a configurable uniqueness check on GA values that can be set when creating a GA class. This uniqueness check ensures that two users cannot share the same value for a specific GA. This check is enforced at the GA class level, so you can have GAs that are checked for uniqueness and others that allow users to share the same value for the same GA.

#### Generic Attribute classes management

The GA classes management page can be reached by clicking on the “Attributes” link in the navbar, and then clicking on the “Manage attribute classes” link. GA classes can then be created, specifying the GA name, description and whether uniqueness must be enforced on the GA values assigned directly to users.

![](https://wiki.italiangrid.it/twiki/pub/VOMS/VOMSAdminUserGuide/ga-classes.png)

#### Managing GAs at the user, group and role level

Once a GA class has been created, GA values can be assigned to users, groups and role within groups. As mentioned above, when one GA is assigned directly to a user, the (name,value) couple is added by VOMS to the attribute certificate returned to user. When a GA is assigned to a group, or role within a group, such (name, value) pair ends up in the Attribute Certificate of all the VO members belonging to that group (or that have such role within a group).

#### Search GA assignments

VOMS Admin implements search over user GA assignments, so that an administrator can easily know the status of GA assignments. The search functions deal only with GA assigned directly to user, i.e., group and role assignements search and centralized display is currently not supported.

![](https://wiki.italiangrid.it/twiki/pub/VOMS/VOMSAdminUserGuide/ga-assignments.png)

### Acceptable Usage Policies (AUP) management

Starting with version 2.5, VOMS Admin implements AUP management. AUP acceptance records are linked to each VO membership, to keep track of which version of the AUP was accepted and when.

Each AUP in VOMS Admin has a reacceptance period. Each user's acceptance record is checked against this period and if the record has expired the user is requested to sign again the AUP.

When the user fails to sign the AUP in the allotted time, he/she is suspended.

Finally, VOMS admin provides the possibility to request re-acceptance from users at any time.

#### How to disable AUP management

AUP management can be disabled by disabling the VOMS Admin registration service. To disable the registration service add the --disable-webui-requests flag when configuring a VO with the voms-admin-configure command, or put the following setting:
voms.request.webui.enabled = false
in the /etc/voms/<vo_name>/voms.service.properties.

#### AUP management page

![](https://wiki.italiangrid.it/twiki/pub/VOMS/VOMSAdminUserGuide/aup-management.png)

From the AUP management page is possible to add/remove new versions of the AUP, update the AUP reacceptance period, set which of the managed version is the active one (i.e., the one presented to VO users at signing time) and request reacceptance of the current version from users.

For VOMS Admin basically an AUP is the URL of a text file, so any file on the local filesystem or on a remote web server can be used for the AUP text.

#### Setting the VO AUP url at VO configuration time

The voms-admin-configure --vo-aup-url option can be used to set the URL for the initial version of the VO acceptable usage policy. If this option is not set a template vo-aup file will be created in vo runtime configuration directory /etc/voms-admin/<vo-name>/vo-aup.txt

### The Configuration Info section

The Configuration info section shows configuration information useful for voms clients, like the vomses string for the VO or a mkgridmap example configuration.

![](https://wiki.italiangrid.it/twiki/pub/VOMS/VOMSAdminUserGuide/conf-section.png)

### The Other VOs section

This section provides links to the other VOs configured on the server.