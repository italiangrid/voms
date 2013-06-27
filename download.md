---
layout: default
title: VOMS downloads
---

# VOMS releases

StoRM packages can be obtained from the EMI repository or from the VOMS produt team package repository.

### Repository configuration 

#### EMI 3 

You can find [general EMI 3 installation instructions](https://twiki.cern.ch/twiki/bin/view/EMI/GenericInstallationConfigurationEMI3) on the EMI site, but it basically boils down to installing the EMI repository

	rpm --import http://emisoft.web.cern.ch/emisoft/dist/EMI/3/RPM-GPG-KEY-emi
	wget http://emisoft.web.cern.ch/emisoft/dist/EMI/3/sl5/x86_64/base/emi-release-3.0.0-2.el5.noarch.rpm
	yum localinstall -y emi-release-3.0.0-2.el5.noarch.rpm

Follow the [system administrator guide]({{site.baseurl}}documentation/sysadmin-guide) for detailed installation instructions.

#### VOMS

Note that the VOMS PT repositories only provide the latest version of the certified VOMS packages.
You still need to install EMI3 repositories (as detailed above) for installations to work as expected.

To install the repository files, run the following commands (as root):

    (SL5) # wget http://italiangrid.github.io/voms/repo/voms_sl5.repo -O /etc/yum.repos.d/voms_sl5.repo
    (SL6) # wget http://italiangrid.github.io/voms/repo/voms_sl6.repo -O /etc/yum.repos.d/voms_sl6.repo


## Current release

The current release is [VOMS v. 0.0.0](release-notes-v0_0_0.html).

## Previous releases

### VOMS v. 0.0.0-1

This was the VOMS released in EMI-3.

See the [release notes](http://www.eu-emi.eu/releases/emi-3-montebianco/products/-/asset_publisher/5dKm/content/storm-se-2) on the EMI project web pages.

---

## Testing versions

We are going provide a repository for testing versions, i.e versions for which the development has finished and can be passed to early adopters for the staged roll-out.

---

## Development versions

Development versions are built regularly on our [continuos integration infrastructure](http://radiohead.cnaf.infn.it:9999/view/VOMS/). 

Artifacts for the last commit can be found on our yum repos for [VOMS SL5](http://radiohead.cnaf.infn.it:9999/view/VOMS/job/repo_voms_SL5/lastSuccessfulBuild/artifcact/voms.repo), 
[VOMS Client SL5](http://radiohead.cnaf.infn.it:9999/view/VOMS/job/repo_voms_clients_3_0_SL5/lastSuccessfulBuild/artifact/voms-clients.repo), 
[VOMS SL6](http://radiohead.cnaf.infn.it:9999/view/VOMS/job/repo_voms_SL6/artifacts/voms.repo) or
[VOMS Client SL6](http://radiohead.cnaf.infn.it:9999/view/VOMS/job/repo_voms_clients_3_0_SL6/lastSuccessfulBuild/artifact/voms-clients.repo).