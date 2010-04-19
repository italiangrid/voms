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

#include <sys/types.h>
#include <netdb.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>

extern "C" {
#include "log.h"
}

static char *getid(struct sockaddr *client, char **symbolic, char **port)
{
  char ports[100];

  char      *buffer = NULL;
  socklen_t  bufsize = 50;
  int        result = 0;

  buffer = (char *)malloc(50);
  if (!buffer)
    return NULL;

  while ((result = 
          getnameinfo(client, sizeof(struct sockaddr_storage), buffer, 
                      bufsize, ports, 99, 0)) == EAI_OVERFLOW) {
    char *newbuf = (char*)realloc(buffer, bufsize + 50);

    if (newbuf) {
      bufsize += 50;
      buffer = newbuf;
    }
    else
      break;
  }
  if (result == 0) {
    *symbolic = buffer;
    *port = ports;
  }

  bufsize = 50;
  buffer = (char *)malloc(50);
  if (!buffer) {
    free(*symbolic);
    return NULL;
  }

  while ((result = 
          getnameinfo(client, sizeof(struct sockaddr_storage), buffer, bufsize, NULL, 0, NI_NUMERICHOST)) == EAI_OVERFLOW) {
    char *newbuf = (char*)realloc(buffer, bufsize + 70);

    if (newbuf) {
      bufsize += 70;
      buffer = newbuf;
    }
    else
      break;
  }

  if (result != 0) {
    free(*symbolic);
    return NULL;
  }
  else {
    if (!strcmp(buffer, *symbolic)) {
      free(*symbolic);
      *symbolic = NULL;
    }

    if (strncasecmp(buffer, "::ffff:", 7) == 0) {
      memmove(buffer, buffer + 7, strlen(buffer) -7 + 1);
    }
    return buffer;
  }

  /* Control should never get here */
  return NULL;
}
  
static void logconnection(struct sockaddr *client, void *logh)
{
  char *port = NULL;
  char *ip = NULL;
  char *dns = NULL;

  ip = getid(client, &dns, &port);

  if (ip) {
    if (dns)
      LOGM(VARP, logh, LEV_INFO, T_PRE, 
           "Received connection from: %s (%s):%s\n", dns, ip, port);
    else
      LOGM(VARP, logh, LEV_INFO, T_PRE, "Received connection from: %s:%s\n", 
           ip, port);
  }
  free(ip);
  free(dns);
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

  getaddrinfo(NULL, port, &hints, &address_list);

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

  getaddrinfo(host, port, &hints, &address_list);

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
