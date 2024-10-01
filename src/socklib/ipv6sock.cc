/*********************************************************************
 *
 * Authors: Vincenzo Ciaschini - Vincenzo.Ciaschini@cnaf.infn.it 
 *
 * Copyright (c) Members of the EGEE Collaboration. 2004-2010.
 * See http://www.eu-egee.org/partners/ for details on the copyright holders.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Parts of this code may be based upon or even include verbatim pieces,
 * originally written by other people, in which case the original header
 * follows.
 *
 *********************************************************************/

#include "config.h"

#ifndef _POSIX_SOURCE
#  define _POSIX_SOURCE 1
#endif

#ifndef NI_MAXHOST
#  define NI_MAXHOST 1025
#endif
#ifndef NI_MAXSERV
#  define NI_MAXSERV 32
#endif

#include <sys/types.h>
#include <netdb.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <cstdlib>
#include <cstring>

extern "C" {
#include "log.h"
}

static void logconnection(struct sockaddr *client, void *logh)
{

  char hostname_buf[NI_MAXHOST];
  char port_no_buf[NI_MAXSERV];

  int nameinfo_status = getnameinfo(
      client,
      sizeof(sockaddr_storage),
      hostname_buf, 
      NI_MAXHOST,
      port_no_buf, 
      NI_MAXSERV,
      NI_NUMERICHOST | NI_NUMERICSERV);

  if (nameinfo_status){
    LOGM(VARP, logh, LEV_ERROR, T_PRE,
        "Error resolving name information for current client, no logging.");
    return;
  }

  LOGM(VARP, logh, LEV_INFO, T_PRE, 
      "Received connection from: %s:%s\n", 
      hostname_buf, 
      port_no_buf);
}

int bind_and_listen(char* port, int backlog, void *logh)
{
  int sock = -1;
  unsigned int on  = 1;
  unsigned int off = 0;
  struct addrinfo hints, *address_list, *paddress;

  memset(&hints, 0, sizeof(hints));

  hints.ai_flags    |= AI_PASSIVE;
  hints.ai_family    = AF_UNSPEC;
  hints.ai_socktype  = SOCK_STREAM;

  if (getaddrinfo(NULL, port, &hints, &address_list)){
    LOGM(VARP, logh, LEV_ERROR, T_PRE, "getaddrinfo() failed for port %s!", port);
    return -1;
  }

  paddress = address_list;

  while (paddress) {
    sock = socket(paddress->ai_family, paddress->ai_socktype, 
                  paddress->ai_protocol);

    if (sock == -1) {
      paddress = paddress->ai_next;
      continue;
    }

    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (void *) &on, sizeof(socklen_t));
    if (paddress->ai_family == AF_INET6)
      setsockopt(sock, IPPROTO_IPV6, IPV6_V6ONLY, (void*) &off, sizeof(off));

    if ((bind(sock, paddress->ai_addr, paddress->ai_addrlen) == -1) ||
        (listen(sock, backlog) == -1)) {
      close(sock);
      paddress = paddress->ai_next;
      sock = -1;
      continue;
    }        
    break;
  }

  if (sock == -1)
    LOGM(VARP, logh, LEV_ERROR, T_PRE, "Cannot bind to socket %s!", port);
  freeaddrinfo(address_list);
  return sock;
}

int accept_ipv6(int sock, void *logh)
{
  int newsock = -1;
  struct sockaddr_storage sock_addr;
  struct sockaddr *client = (struct sockaddr *)&sock_addr;
  socklen_t len = sizeof(sock_addr);

  if (sock == -1)
    return -1;

#ifndef HAVE_SOCKLEN_T
  newsock = accept(sock, client, (int*)(&(len)));
#else
  newsock = accept(sock, client, &len);
#endif

  if (newsock != -1) {
    logconnection(client, logh);
  }
  return newsock;
}

int sock_connect(const char *host, char *port)
{
  struct addrinfo hints, *address_list, *paddress;
  int sock = -1;
  unsigned int on  = 1;
  unsigned int off = 0;

  memset(&hints, 0, sizeof(hints));

  hints.ai_family = PF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;

  if (getaddrinfo(host, port, &hints, &address_list)) {
    return -1;
  }

  paddress = address_list;

  while (paddress) {
    sock = socket(paddress->ai_family, paddress->ai_socktype, 
                  paddress->ai_protocol);

    if (sock == -1) {
      paddress = paddress->ai_next;
      continue;
    }

    
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (void *) &on, sizeof(on));
    if (paddress->ai_family == AF_INET6)
      setsockopt(sock, IPPROTO_IPV6, IPV6_V6ONLY, (void*) &off, sizeof(off));

    if (connect(sock, paddress->ai_addr, paddress->ai_addrlen) == -1) {
      close(sock);
      paddress = paddress->ai_next;
      continue;
    }        
    break;
  }

  freeaddrinfo(address_list);

  return sock;
}
