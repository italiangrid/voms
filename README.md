# VOMS

The Virtual Organization Membership Service (VOMS) is an attribute authority
which serves as central repository for VO user authorization information,
providing support for sorting users into group hierarchies, keeping track of
their roles and other attributes in order to issue trusted attribute
certificates and SAML assertions used in the Grid environment for authorization
purposes.

This repository hosts VOMS server, clients and C++ APIs.

## Build matrix

| Distribution | gcc version (C++ standard) | OpenSSL version |
| ------------ | -------------------------- | --------------- |
| Ubuntu 20.04 | 9.3 (C++14)                | 1.1.1f          |
| Ubuntu 22.04 | 11.2 (C++17)               | 3.0.2           |
| Ubuntu 24.04 | 13.2 (C++17)               | 3.0.13          |
| Ubuntu 26.04 | 15.2 (C++20)               | 3.5.5           |
| AlmaLinux  8 | 8.5 (C++14)                | 1.1.1k          |
| AlmaLinux  9 | 11.5 (C++17)               | 3.5.5           |
| AlmaLinux 10 | 14.3 (C++17)               | 3.5.5           |
| Fedora 45    | 16.1 (C++20)               | 4.0.1           |

## Documentation

See the [VOMS website](https://italiangrid.github.io/voms).

# Support

Submit a ticket in [GGUS](https://ggus.eu/pages/ticket.php) targeted at the VOMS EMI support unit.

# License

Licensed under the Apache License, Version 2.0 (the "License"); you may not use
this project except in compliance with the License. You may obtain a copy of
the License at http://www.apache.org/licenses/LICENSE-2.0.

Unless required by applicable law or agreed to in writing, software distributed
under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
CONDITIONS OF ANY KIND, either express or implied. See the License for the
specific language governing permissions and limitations under the License.
