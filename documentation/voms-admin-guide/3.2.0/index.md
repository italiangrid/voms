---
layout: default
title: VOMS Admin user guide
version: 3.2.0
---

# VOMS Admin user guide

Version: {{ page.version }}

### Table of contents

- [The VOMS Admin web application](#WebApplication)
- [The VOMS Admin authorization framework](#authz)
- [Using the command line utilities](#VOMSAdminCLI)

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

## The VOMS Admin authorization framework<a name="authz">&nbsp;</a>

In VOMS-Admin, each operation that access or modify the VOMS database is authorized via the VOMS-Admin Authorization framework. 

Access Control Lists (ACLs) are linked to VOMS contexts to enforce authorization decisions on such contexts. A Context is either a VOMS group, or a VOMS role within a group. Each Context has a linked ACL, which is a set of access control entries (ACEs). An ACE maps a VOMS administrator to a set of permissions.

A *VOMS Administrator* may be:

* A VO administrator registered in the VOMS database for the VO;
* A VO user;
* A VOMS FQAN, i.e. any user who belongs to a VO group or has a given role;
* Any authenticated user (i.e., any user who presents a certificate issued by a trusted CA).

A *VOMS Permission* is a fixed-length sequence of permission flags that describe the set of permissions a VOMS Administrator has in a specific context. The following table explains in detail the name and meaning of these permission flags:

* CONTAINER_READ, CONTAINER_WRITE: These flags are used to control access to the operations that list/alter the VO internal structure (groups and roles list/creations/deletions, user creations/deletions).
* MEMBERSHIP_READ, MEMBERSHIP_WRITE: These flags are used to control access to operations that manage/list membership in group and roles.
* ATTRIBUTES_READ,ATTRIBUTES_WRITE: These flags are used to control access to operations that mange generic attributes (at the user, group, or role level).
* ACL_READ,ACL_WRITE,ACL_DEFAULT: These flags are used to control access to operations that manage VO ACLs and default ACLs.
* REQUESTS_READ, REQUESTS_WRITE: These flags are used to control access to operations that manage subscription requests regarding the VO, group membership, role assignment etc...
* PERSONAL_INFO_READ, PERSONAL_INFO_WRITE: The flags are used to control access to user personal information stored in the database.
* SUSPEND: This flag controls who can suspend other users.

Each operation on the VOMS database is authorized according to the above set of permissions, i.e., whenever an administrator tries to execute such operation, its permissions are matched with the operation's set of required permission in order to authorize the operation execution.

### ACL inheritance and VOMS groups

Children groups, at creation time, inherit the parent's group ACL.
It is possible to change this behaviour leveraging via _Default ACLs_. When the Default ACL is defined for a group, children groups inherit the Default ACL defined at the parent level instead of the parent's group ACL. So, Default ACLs are useful *only if an administrator wants the ACL of children groups to be different from the one of the parent's group*.

### VOMS Admin operations and required permissions

In this section, we describe the required permissions for the most comon voms-admin operations according to this notation:

<table>
  <tr>
    <th>Symbol</th>
		<th>Meaning</th>
  </tr>
  <tr>
    <td>/vo</td>
		<td>The VO root group</td>
  </tr>
  <tr>
    <td>(g,R)</td>
		<td>The context identified by role R within group g</td>
  </tr>
  <tr>
    <td>(g ➝ g')</td>
		<td>All the voms groups that lie in the path from group g to group g' included according to the parent-child relationship defined between voms group</td>
  </tr>
  <tr>
    <td>r,w,d,s</td>
		<td> Read permission, Write permission, default permission (applies only to ACL permissions), suspend permission</td>
  </tr>
  <tr>
    <td>parent(g)</td>
		<td>Group g's parent group</td>
  </tr>
  <tr>
    <td>C:, M:, Attrs:, Acl:, Req:, PI:</td>
		<td>Container, Membership, Attributes, ACL, Requests and Personal Information permissions short names</td>
  </tr>
</table>

The table below lists operations on the left and required permissions on the right, expressed in the form of (VOMSContext, VOMSPermission) couples.

<table>
  <tr>
    <th>Operation</th>
		<th>Required permissions</th>
		<th>Explanation</th>
  </tr>
  <tr>
    <td>Create/delete user</td>
		<td>(/vo,C:rw M:rw)</td>
		<td>Container and membership read and write access on the root group</td>
  </tr>
  <tr>
    <td>Create/delete group g</td>
		<td>(/vo,C:rw) , (/vo → parent(parent(g)), C:r) , (parent(g), C:rw)</td>
		<td> Container rw access on the root group, container read access on all to groups leading to g's parent group and Container rw access in g's parent group</td>
  </tr>
	<tr>
    <td>List group g subgroups</td>
		<td>(/vo → g, C: r)</td>
		<td>Container read access on all the groups leading to g
		</td>
  </tr>
	<tr>
    <td>Create/delete role</td>
		<td>(/vo, C:rw)</td>
		<td>Container read/write access on the VO root group</td>
  </tr>
	<tr>
    <td>List VO roles</td>
		<td>(/vo, C:r)</td>
		<td>Container read access on the VO root group</td>
  </tr>
	<tr>
    <td>Add remove/member to group g</td>
		<td>(/vo → parent(parent(g)), C:r), (g, M:rw)</td>
		<td>Container read access on all the groups leading to g's parent, and Membership rw access on g
		</td>
  </tr>
	<tr>
    <td>List group g members</td>
		<td>(/vo → parent(parent(g)), C:r), (g, M:r)</td>
		<td>Container read access on all the groups leading to g's parent and Membership read access on g</td>
  </tr>
	<tr>
    <td>Assign/dismiss role R in group g</td>
		<td>(/vo → parent(parent(g)), C:r), ((g,R), M:rw)</td>
		<td>	 Container read access on all the groups leading to g's parent and Membership rw access on role R within g</td>
  </tr>
	<tr>
    <td>List members wirh role R in group g</td>
		<td>(/vo → parent(parent(g)), C:r), ((g,R), M:r)</td>
		<td>Container read access on all the groups leading to g's parent and Membership read access on role R within g</td>
  </tr>
	<tr>
    <td>Set/delete user generic attribute</td>
		<td>(/vo, Attrs:rw)</td>
		<td>Attribute rw access on the VO root group</td>
  </tr>
	<tr>
    <td>List user generic attributes</td>
		<td>(/vo, Attrs: r)</td>
		<td>Attribute read access on the VO root group
		</td>
  </tr>
	<tr>
    <td>List group g generic attributes</td>
		<td>(/vo → parent(parent(g)), C:r), (/vo, Attrs:r), (g, Attrs:r)</td>
		<td>Container read access on all the groups leading to g's parent, Attributes read access on the VO root group and on group g</td>
  </tr>
	<tr>
    <td>Set/delete group g attributes</td>
		<td>(/vo → parent(parent(g)), C:r), (/vo, Attrs:rw), (g, Attrs:rw)</td>
		<td>Container read access on all the groups leading to g's parent, Attributes read access on the VO root group and on group g</td>
  </tr>
	<tr>
    <td>Set/delete role R attributes within group g</td>
		<td>(/vo → parent(parent(g)), C:r), (/vo, Attrs:rw), ((g,R), Attrs:rw)</td>
		<td>Container read access on all the groups leading to g's parent, Attributes rw access on the VO root group and on role R withing g</td>
  </tr>
	<tr>
    <td>Edit ACL for group g</td>
		<td>(/vo → parent(parent(g)), C:r), (g, ACL:rw)</td>
		<td>Container read access on all the groups leading to g's parent, ACL rw access on group g</td>
  </tr>
	<tr>
    <td>Edit ACL for group g</td>
		<td>(/vo → parent(parent(g)), C:r), (g, ACL:rw)</td>
		<td>Container read access on all the groups leading to g's parent, ACL rw access on group g</td>
  </tr>
	<tr>
    <td>List ACL for group g</td>
		<td>(/vo → parent(parent(g)), C:r), (g, ACL:r)</td>
		<td>Container read access on all the groups leading to g's parent, ACL read access on group g</tr>
	<tr>
    <td>Suspend a user</td>
		<td>(/vo, s)</td>
		<td>Suspend flag on the VO root group</td>
  </tr>
</table>


## Using the command line utilities<a name="VOMSAdminCLI">&nbsp;</a>

### The voms-db-util command

The `voms-db-util` command is used to manage the deployment of the VOMS database and to add/remove administrators without requriing voms-admin VOs to be active. See the `voms-db-util` man page
for more details.

### The voms-admin command line client

VOMS Admin comes with a python command line client utility, called voms-admin, that can be used to perform most of the operations on the VOMS database that are implemented by the Web interface.

`voms-admin` uses the UNIX effective user ID to choose which X509 credential it must use to connect to a (possibly remote) VOMS Admin instance. When ran as root, `voms-admin` uses the host credentials found in /etc/gridsecurity. When running as a normal user, `voms-admin does the following:`

* if the X509_USER_PROXY environment variable is set, voms-admin uses the credentials pointed by such environment variable,
* otherwise If a proxy exists in /tmp, the proxy is used,
* otherwise if the X509_USER_CERT environment variable is set, voms-admin uses the credentials pointed by X509_USER_CERT and X509_USER_KEY environment variables,
* otherwise the usercert.pem and userkey.pem credentials from the $HOME/.globus are used.

A user can get the list of supported commands by typing:

```bash
voms-admin --list-commands
```

The output will be something like:

```bash
Supported commands list:

ROLE ASSIGNMENT COMMANDS:

  assign-role
  dismiss-role
  list-users-with-role
  list-user-roles

ROLE MANAGEMENT COMMANDS:

  list-roles
  create-role
  delete-role

ATTRIBUTE CLASS MANAGEMENT COMMANDS:

  create-attribute-class
  delete-attribute-class
  list-attribute-classes

GROUP MEMBERSHIP MANAGEMENT COMMANDS:

  add-member
  remove-member
  list-members

USER MANAGEMENT COMMANDS:

  list-users
  create-user
  delete-user

ACL MANAGEMENT COMMANDS:

  get-ACL
  get-default-ACL
  add-ACL-entry
  add-default-ACL-entry
  remove-ACL-entry
  remove-default-ACL-entry

GENERIC ATTRIBUTE ASSIGNMENT COMMANDS:

  set-user-attribute
  delete-user-attribute
  list-user-attributes
  set-group-attribute
  set-role-attribute
  delete-group-attribute
  list-group-attributes
  list-role-attributes
  delete-role-attribute

GROUP MANAGEMENT COMMANDS:

  list-groups
  list-sub-groups
  create-group
  delete-group
  list-user-groups
```

Detailed help about individual commands can be obtained issuing the following command:

```bash
voms-admin --help-command <command name>
```

The help message contains examples for typical use cases. For example, asking help about the create-user command produces the following output:

```bash
$ voms-admin --help-command create-user

create-user CERTIFICATE.PEM
	
        Registers a new user in VOMS. 
        
        If you use the --nousercert  option, then four parameters are 
        required (DN CA CN MAIL) to create the user. 
        
        Otherwise these parameters are extracted automatically from the
        certificate. 
        
        Examples: 
        
        voms-admin --vo test_vo create-user .globus/usercert.pem 
        
        voms-admin --nousercert --vo test_vo create-user \ 
        'My DN' 'My CA' 'My CN' 'My Email'
```

A user can get help about all the commands provided by voms-admin by typing:

```bash
voms-admin --help-commands
```
