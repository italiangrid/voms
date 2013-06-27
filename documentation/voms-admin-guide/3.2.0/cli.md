---
layout: default
title: VOMS Admin CLI
version: 3.2.0
---

## The VOMS Admin command line utilities<a name="VOMSAdminCLI">&nbsp;</a>

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