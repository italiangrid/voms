# VOMS

The Virtual Organization Membership Service (VOMS) is an attribute authority
which serves as central repository for VO user authorization information,
providing support for sorting users into group hierarchies, keeping track of
their roles and other attributes in order to issue trusted attribute
certificates and SAML assertions used in the Grid environment for authorization
purposes.

This Github repository hosts the source code of

- The VOMS server
- The C++ and C VOMS APIs
- The VOMS clients (i.e. voms-proxy-init)

# Build dependencies 

In order to build VOMS you will need at least the following packages:

- A reasonably recent version of the autotools (and libtool)
- bison
- OpenSSL devel package > 0.9.8
- A resonably recent version of expat-devel
- pkg-config

In order to build the pdf documentation you will need as well:

- libxslt and docbook-style-xsl (if you want to build the pdf documentation)
- doxygen

# Build instructions

```bash ./autogen.sh ./configure make make install ```

In case you want to build rpm packages, run: ```bash make rpm ```

To build debian packages run ```bash make deb ```

The usual rpm and deb packaging tools are required for the packaging to be
successfull.

# Support

Having problem with VOMS? Submit a ticket in
[GGUS](https://ggus.eu/pages/ticket.php) targeted at the VOMS EMI support unit.

# License

Licensed under the Apache License, Version 2.0 (the "License"); you may not use
this project except in compliance with the License. You may obtain a copy of
the License at http://www.apache.org/licenses/LICENSE-2.0.

Unless required by applicable law or agreed to in writing, software distributed
under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
CONDITIONS OF ANY KIND, either express or implied. See the License for the
specific language governing permissions and limitations under the License.
