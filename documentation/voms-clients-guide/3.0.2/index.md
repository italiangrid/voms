---
layout: default
title: VOMS Client Guide
version: 3.0.2
---

# VOMS Clients guide

Version: {{page.version}}

#### Table of contents
* [Installing the clients](#install)
* [Configuring VOMS trust anchors](#voms-trust)
* [Configuring the VOMS server endpoints](#vomses)
* [User credentials](#cred)
* [Creating a VOMS proxy](#voms-proxy-init)
* [Showing VOMS attributes information](#voms-proxy-info)
* [Destroying a VOMS proxy](#voms-proxy-destroy)

## Installing the clients <a name="install">&nbsp;</a>

To install the VOMS clients, configure the EMI 3 repositories as appropriate
for the distribution where you will install the VOMS clients.

On Scientific Linux 5 or 6, voms clients are installed with the following command:

```
yum install voms-clients3
```

On Debian6 use the following command:

```
apt-get install voms-clients3
```

## Configuring VOMS trust anchors <a name="voms-trust">&nbsp;</a>

VOMS clients need local configuration to validate the signature on Attribute Certificates
issued by trusted VOMS servers.

The VOMS clients and APIs look for trust information in the `/etc/grid-security/vomsdir` directory.

The `vomsdir` directory contains a directory for each trusted VO. Inside each VO directory two types 
of files can be found:

* An _LSC file_ contains a description of the certificate chain of the 
certificate used by a VOMS server to sign VOMS attributes.
* An _X509 certificates_ used by a VOMS server to sign attributes.

These files are commonly named using the following pattern:

```
<hostname>.lsc
<hostname>.pem
```
where `hostname` is the host where the VOMS server is running.

When both lsc and pem files are present for a given VO and hostname, the lsc file takes precedence.

The LSC file contains a list of X.509 subject strings, one on each line, encoded in OpenSSL slash-separated syntax, describing the certificate chain (up and including the CA that issued the certificate). For instance, the voms.cnaf.infn.it VOMS server has the following LSC file:
```
/C=IT/O=INFN/OU=Host/L=CNAF/CN=voms.cnaf.infn.it
/C=IT/O=INFN/CN=INFN CA
```

For more details see the `vomsdir` man page.

## Configuring VOMS server endpoints <a name="vomses">&nbsp;</a>

The list of known VOMS server is maintained in `vomses` files. A `vomses` file is 
a simple text file which contains one or more lines formatted as follows:

```
"vo_name" "hostname" "port" "dn" "alias"
```

where `vo_name` is the name of the VO served by the VOMS server, 
`hostname` is the hostname where the VOMS server is running, 
`port` is the port where the VOMS server is listening for incoming requests,
`dn` is the subject of the certificate of the VOMS server, and
`alias` is an alias that can be used for this VOMS server (this is typically identical to the vo_name).

System wide VOMSES configuration is maintained in the `/etc/vomses` file or directory. If
`/etc/vomses` is a directory, all the files contained in such directory are parsed looking for
VOMS contact information.

A user can define its custom vomses configuration in the `~/.glite/vomses` file or directory,
which will be parsed in the same way as just described.

For more details on how to configure vomses files on the system, see the `vomses` man page.

## User credentials <a name="cred">&nbsp;</a>

While user credentials may be put anywhere, and then their location passed to 
`voms-proxy-init` via the appropriate options, there are obviously default values.

User credentials should be put in the `$HOME/.globus`.

Certificates encoded in PKCS12 and PEM formats are correctly handled by the VOMS clients.

The default path for looking up PKCS12 credentials is:

```
usercred.p12
```

For PEM credentials the following paths are used:

```
usercert.pem (certificate)
userkey.pem (private key)
```

In case both the PEM and PKCS12 formats are present, PEM takes precedence. 

The user certiﬁcate must at the most have permission 644, while the private key should be 400.

## Creating a proxy <a name="voms-proxy-init">&nbsp;</a>

The command `voms-proxy-init` is used to contact the VOMS server and retrieve an AC 
containing user attributes that will be included in the proxy certiﬁcates.

```
$ voms-proxy-init --voms voname
```

where `voname` is the name of the VO to which the user belongs. This will create a proxy containing all the groups
to which the user belongs. The `-voms` option may be speciﬁed multiple times in case the user belongs to more than one VO.

Omitting the `–voms` option results in the creation of a plain proxy, as you would get running `grid-proxy-init`.

No roles are ever include in proxy by default. In case they are needed, they must be
explicitly requested. For example, to request the role sgm in the `/test/italian group`, the following
syntax should be used:

```
$ voms-proxy-init --voms test:/test/italian/Role=sgm
```

thus obtaining a role that will be included in the AC, in addition to all the other information that will be
normally present. In case multiple roles are needed, the `-voms` option may be used several times.

By default, all FQANs explicitly requested on the command line will be present in the returned credentials,
if they were granted, and in the exact order speciﬁed, with all other FQANs following in an unspeciﬁed
ordering. If a speciﬁc order is needed, it should be explicitly requested via the -order option. For
example, the following command line:

```
$ voms-proxy-init --voms test:/test/Role=sgm --order /test
```

asks for the Role sgm in the root group, and speciﬁes that the resulting AC should begin with membership
in the root group instead, while posing no requirements on the ordering of the remaining FQANs. This
also means that with the above command line there is no guarantee that the role will end up as the second
FQAN. If this is desired, use the following command line instead:

```
$ voms-proxy-init --voms test:/test/Role=sgm --order /test --order /test/Role=sgm
```

The validity of an AC created by VOMS will generally be as long as the proxy which contains it. However,
this cannot always be true. For starters, the VOMS server is conﬁgured with a maximum validity for all
the ACs it will create, and a request to exceed it will simply be ignored. If this happens, the output of
voms-proxy-init will indicate the fact.

For example, in the following output (slightly reformatted for a shorter line then on screen):

```
$ voms-proxy-init --voms valerio --vomslife 50:15
Enter GRID pass phrase:
Your identity: /C=IT/O=INFN/OU=Personal Certificate/L=CNAF/CN=Vincenzo Ciaschini
Creating temporary proxy .................................... Done
Contacting datatag6.cnaf.infn.it:50002
[/C=IT/O=INFN/OU=Host/L=CNAF/CN=datatag6.cnaf.infn.it] "valerio" Done
Warning: datatag6.cnaf.infn.it:50002:
The validity of this VOMS AC in your proxy is shortened to 86400 seconds!
Creating proxy ......................................... Done
Your proxy is valid until Fri Sep 8 01:55:34 2006
```

You can see that the life of the voms AC has been clearly shortened to 24 hours, even though 50 hours
and 15 minutes had been requested.

If your certiﬁcate is not in the default place, you may specify it explicitly by using the –cert and –key
options, like in the following example:

```
voms-proxy-init --voms valerio --cert \$HOME/cert.pem --key \$HOME/key.pem
```

See `voms-proxy-init --help` or the man page for a complete list of available options.

## Showing VOMS attributes information <a name="voms-proxy-info">&nbsp;</a>

Once a proxy has been created, the `voms-proxy-info` command allowes the user to retrieve several
information from it. The two most basic uses are:

```
$ voms-proxy-info
subject : /C=IT/O=INFN/OU=Personal Certificate/L=CNAF/CN=Vincenzo Ciaschini/CN=proxy
issuer : /C=IT/O=INFN/OU=Personal Certificate/L=CNAF/CN=Vincenzo Ciaschini
identity : /C=IT/O=INFN/OU=Personal Certificate/L=CNAF/CN=Vincenzo Ciaschini
type : proxy
strength : 512 bits
path : /tmp/x509up_u502
timeleft : 10:33:52
```

which, as you can see, prints the same information that would be printed by a plain grid-proxy-info,
and then there is:

```
$ voms-proxy-info --all
subject : /C=IT/O=INFN/OU=Personal Certificate/L=CNAF/CN=Vincenzo Ciaschini/CN=proxy
issuer : /C=IT/O=INFN/OU=Personal Certificate/L=CNAF/CN=Vincenzo Ciaschini
identity : /C=IT/O=INFN/OU=Personal Certificate/L=CNAF/CN=Vincenzo Ciaschini
type : proxy
strength : 512 bits
path : /tmp/x509up_u502
timeleft : 11:59:59
=== VO valerio extension information ===
VO : valerio
subject : /C=IT/O=INFN/OU=Personal Certificate/L=CNAF/CN=Vincenzo Ciaschini
issuer : /C=IT/O=INFN/OU=Host/L=CNAF/CN=datatag6.cnaf.infn.it
attribute : /valerio
attribute : /valerio/asdasd
attribute : /valerio/qwerty
attribute : attributeOne = 111 (valerio)
attribute : attributeTwo = 222 (valerio)
timeleft : 11:59:59
uri : datatag6.cnaf.infn.it:15000
```

which prints everything that there is to know about the proxy and the included ACs. 

Several options enable the user to select just a subset of the information shown here. 
See `voms-proxy-info --help` or the man page for a complete list of available options.

## Destroying a proxy <a name="voms-proxy-destroy">&nbsp;</a>

The `voms-proxy-destroy` command erases an existing proxy from the system. Its basic use is:

```
$ voms-proxy-destroy
```

See `voms-proxy-destroy --help` or the man page for a complete list of available options.
