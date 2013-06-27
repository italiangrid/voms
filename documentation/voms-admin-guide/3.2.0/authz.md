---
layout: default
title: VOMS Admin Authorization framework
version: 3.2.0
---

## The VOMS Admin authorization framework<a name="authz">&nbsp;</a>

In VOMS-Admin, each operation that access or modify the VOMS database is authorized via the VOMS-Admin Authorization framework. 

Access Control Lists (ACLs) are linked to VOMS contexts to enforce authorization decisions on such contexts. A Context is either a VOMS group, or a VOMS role within a group. Each Context has a linked ACL, which is a set of access control entries (ACEs). An ACE maps a VOMS administrator to a set of permissions.

A *VOMS Administrator* may be:

* A VO administrator registered in the VOMS database for the VO;
* A VO user;
* A VOMS FQAN, i.e. any user who belongs to a VO group or has a given role;
* Any authenticated user (i.e., any user who presents a certificate issued by a trusted CA).

A *VOMS Permission* is a fixed-length sequence of permission flags that describe the set of permissions a VOMS Administrator has in a specific context. The following table explains in detail the name and meaning of these permission flags:


<table>
	<thead>
		<th>Flag name</th>
		<th>Meaning</th>
	</thead>
	<tbody>
		<tr>
			<td>CONTAINER_READ<br/>CONTAINER_WRITE</td>
			<td>These flags are used to control access to the operations that list/alter the VO internal structure (groups and roles list/creations/deletions, user creations/deletions)</td>
		</tr>
		<tr>
			<td>MEMBERSHIP_READ<br/>MEMBERSHIP_WRITE</td>
			<td>These flags are used to control access to operations that manage/list membership in group and roles.</td>
		</tr>
		<tr>
			<td>ATTRIBUTES_READ</br>ATTRIBUTES_WRITE</td>
			<td>These flags are used to control access to operations that mange generic attributes (at the user, group, or role level).</td>
		</tr>
		<tr>
			<td>ACL_READ</br>ACL_WRITE</br>ACL_DEFAULT</td>
			<td>These flags are used to control access to operations that manage VO ACLs and default ACLs.</td>
		</tr>
		<tr>
			<td>REQUESTS_READ</br>REQUESTS_WRITE</td>
			<td>These flags are used to control access to operations that manage subscription requests regarding the VO, group membership, role assignment etc...</td>
		</tr>
		<tr>
			<td>PERSONAL_INFO_READ</br>PERSONAL_INFO_WRITE</td>
			<td>The flags are used to control access to user personal information stored in the database.</td>
		</tr>
		<tr>
			<td>SUSPEND</td>
			<td>This flag controls who can suspend other users.</td>
		</tr>
	</tbody>
</table>

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