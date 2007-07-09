 /*********************************************************************
 *
 * Authors: Vincenzo Ciaschini - Vincenzo.Ciaschini@cnaf.infn.it 
 *
 * Copyright (c) 2002, 2003 INFN-CNAF on behalf of the EU DataGrid.
 * For license conditions see LICENSE file or
 * http://www.edg.org/license.html
 *
 * Parts of this code may be based upon or even include verbatim pieces,
 * originally written by other people, in which case the original header
 * follows.
 *
 *********************************************************************/
/* $Id:*/

/**
 * @file tokens.c
 * @brief The implementation for token transmission and reception.
 * This file implements a couple of methods providing functionality
 * to send and receive tokens.
 * @author Salvatore Monforte salvatore.monforte@ct.infn.it
 * @author comments by Marco Pappalardo marco.pappalardo@ct.infn.it and Salvatore Monforte
 */

#include "config.h"
#include "replace.h"

#include <stdlib.h>
#include <stdio.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>
#include <unistd.h>
#include <globus_gss_assist.h>

static int alarmed = 0;
int sockalarmed = 0;

typedef enum { GSI, SSL2, TLS, SSL_GLOBUS} mode_type;

static mode_type mode = GSI; /* Global, since it needs to be shared between 
                                send and receive. */

static ssize_t myrecv(int fd, void *buf, size_t len, int flags);
static ssize_t protocol_recv(int fd, unsigned char beginning[4], void **buf, size_t *len, mode_type mode);
static ssize_t gsi_recv(int fd, unsigned char beginning[4], void **buf, size_t *len, int flags);
static ssize_t ssl_globus_recv(int fd, unsigned char beginning[4], void **buf, size_t *len, int flags);
static ssize_t ssl2_recv(int fd, unsigned char beginning[4], void **buf, size_t *len, int flags);
static ssize_t tls_recv(int fd, unsigned char beginning[4], void **buf, size_t *len, int flags);
static mode_type detect_mode(unsigned char beginning[4]);

#ifdef HAVE_SIGACTION
static void sigact_handler()
{
  alarmed = 1;
}
#else
static void sigalarm_handler(int sig)
{
  alarmed = 1;
}
#endif

/**
 * Send a gss token.
 * This method send gss tokens using GSI socket objects.
 * @param arg pointer to the descriptor of the socket.
 * @param token pointer to the token buffer to be sent.
 * @param token_length token buffer length
 * @returns the number of bytes sent, or -1 on failure.
 */
int send_token(void *arg, void *token, size_t token_length)
{
    size_t			num_written = 0;
    ssize_t			n_written;
    int 			fd = *( (int *) arg );
    unsigned char		token_length_buffer[4];

    if (mode == GSI) {
      /* encode the token length in network byte order: 4 byte, big endian */
      token_length_buffer[0] = (unsigned char) ((token_length >> 24) & 0xffffffff);
      token_length_buffer[1] = (unsigned char) ((token_length >> 16) & 0xffffffff);
      token_length_buffer[2] = (unsigned char) ((token_length >>  8) & 0xffffffff);
      token_length_buffer[3] = (unsigned char) ((token_length      ) & 0xffffffff);

      /* send the token length */

      while(num_written < 4) {
        n_written = send(fd, token_length_buffer + num_written, 4 - num_written,0);
      
        if(n_written < 0) {
          if(errno == EINTR)
            continue;
          else
            return -1;
        }
        else
          num_written += n_written;
      }
    }
    /* send the token */

    num_written = 0;
    while(num_written < token_length) {
      n_written = send(fd, ((u_char *)token) + num_written, token_length - num_written,0);
       
      if(n_written < 0) {
        if(errno == EINTR)
          continue;
        else
          return -1;
      }
      else
        num_written += n_written;
    }
    
    return 0;
}



static ssize_t myrecv(int s, void *buf, size_t len, int flags)
{
  int alrm = 0;
  ssize_t n_read = 0;
  size_t num_read = 0;

  while (num_read < len) {
    if (sockalarmed)
      alarm(sockalarmed);

    n_read = recv(s, buf + num_read, len - num_read, flags);
    alarm(0);

    alrm = alarmed;
    alarmed = 0;

    if (alrm)
      return -1;

    if (n_read < 0) {
      if (errno == EINTR && !alrm)
        continue;
      else
        return -1;
    }
    else if (n_read == 0)
      return 0;

    num_read += n_read;
  }

  return num_read;
}


/**
 * Receive a gss token.
 * This method receives gss tokens using GSI socket objects.
 * @param arg pointer to the descriptor of the socket.
 * @param token pointer to the token buffer to fill with received token.
 * @param token_length token buffer length
 * @returns the number of bytes recieved, or -1 on failure.
 */
int get_token(void *arg, void **token, size_t *token_length)
{
    size_t			num_read = 0;
    ssize_t			n_read;
    int 			fd = *( (int *) arg );
    unsigned char		token_length_buffer[4];
    int alrm = 0; 

#ifdef HAVE_SIGACTION
    struct sigaction action;

    action.sa_handler = sigact_handler;
    action.sa_flags = 0;
    sigemptyset(&(action.sa_mask)); 	/* ignore all known signals */
    sigaction(SIGALRM,&action,NULL);  /* ensures that SA_RESTART is NOT set */
#else
    signal(SIGALRM, sigalarm_handler); 
#endif

    /* read the token length */
    n_read = myrecv(fd, token_length_buffer, 4, 0);

    if (n_read < 0)
      return -1;
    else if (n_read == 0)
      return GLOBUS_GSS_ASSIST_TOKEN_EOF;

    mode = detect_mode(token_length_buffer);

    if (protocol_recv(fd, token_length_buffer, token, token_length, mode) != -1)
      return 0;

    return -1;
}

static mode_type detect_mode(unsigned char beginning[4]) 
{
  if (beginning[0] >= 20 && beginning[0] <= 23) {
    /*
     * either TLS or SSL3.  They are equivalent for our purposes.
     */
    return TLS;
  }

  if (beginning[0] == 26)
    return SSL_GLOBUS; /* Globus' own SSL variant */

  if (beginning[0] & 0x80) {
  /*
   * The data length of an SSL packet is at most 32767.
   */
    return SSL2;
  }

#if 0
  if (beginning[0] & 0xc0)
    return SSL2;
#endif

  return GSI;
}

static ssize_t tls_recv(int fd, unsigned char beginning[4], void **buf, size_t *len, int flags)
{
  ssize_t nread = 0;
  unsigned char value = '\0';
  size_t size;
  unsigned char *buffer = NULL;

  nread = myrecv(fd, &value, 1, flags);

  if (nread <= 0)
    return -1;

  size = beginning[3] << 8 | value;

  buffer = (unsigned char *)malloc(size+5);

  if (!buffer)
    return -1;

  memcpy(buffer, beginning, 4);

  buffer[4] = value;

  nread = myrecv(fd, buffer+5, size, 0);

  if (nread != size) {
    free(buffer);
    return -1;
  }

  *buf = buffer;
  *len = size+5;
  return size+5;
}

static ssize_t ssl2_recv(int fd, unsigned char beginning[4], void **buf, size_t *len, int flags)
{
  ssize_t nread = 0;
  size_t size;
  unsigned char *buffer = NULL;

  /* 2 bytes header */
  size = ((beginning[0] & 0x7f) << 8) | beginning[1];
  buffer = (unsigned char *)malloc(size+2);

  if (!buffer)
    return -1;

  memcpy(buffer, beginning, 4);

  nread = myrecv(fd, buffer + 4, size -2, 0);

  if (nread != (size - 2)) {
    free(buffer);
    return -1;
  }

  *buf = buffer;
  *len = size + 2;
  return size+2;

}

static ssize_t ssl_globus_recv(int fd, unsigned char beginning[4], void **buf, size_t *len, int flags)
{
  ssize_t nread = 0;
  unsigned char value = '\0';
  size_t size;
  size_t hashsize;
  unsigned char *hashbuffer = NULL;
  unsigned char *buffer = NULL;

  nread = myrecv(fd, &value, 1, flags);

  if (nread <= 0)
    return -1;

  hashsize = beginning[3] << 8 | value;
  hashbuffer = (unsigned char*)malloc(hashsize+12);

  if (!hashbuffer)
    return -1;

  nread = myrecv(fd, hashbuffer, hashsize, flags);

  if (nread <= 0) {
    free(hashbuffer);
    return -1;
  }

  size = hashbuffer[hashsize-4] << 24 |
    hashbuffer[hashsize-3] << 16 |
    hashbuffer[hashsize-2] << 8 |
    hashbuffer[hashsize-1];

  buffer = (unsigned char *)malloc(size+hashsize+5);

  if (!buffer) {
    free(hashbuffer);
    return -1;
  }

  memcpy(buffer, beginning, 4);

  buffer[4] = value;

  memcpy(buffer+5, hashbuffer, hashsize);

  free(hashbuffer);

  nread = myrecv(fd, buffer+hashsize, size, 0);

  if (nread != size) {
    free(buffer);
    return -1;
  }

  *buf = buffer;
  *len = size+hashsize+5;
  return size+hashsize+5;
}

static ssize_t gsi_recv(int fd, unsigned char beginning[4], void **buf, size_t *len, int flags)
{
  ssize_t nread = 0;
  size_t size = 0;
  unsigned char *buffer = NULL;

  size  = (((size_t) beginning[0]) << 24) & 0xffffffff;
  size |= (((size_t) beginning[1]) << 16) & 0xffffffff;
  size |= (((size_t) beginning[2]) <<  8) & 0xffffffff;
  size |= (((size_t) beginning[3])      ) & 0xffffffff;

  buffer = (unsigned char *)malloc(size);

  if (!buffer)
    return -1;

  nread = myrecv(fd, buffer, size, 0);

  if (nread != size) {
    free(buffer);
    return -1;
  }

  *buf = buffer;
  *len = size;
  return size;
}

static ssize_t protocol_recv(int fd, unsigned char beginning[4], void **buf, size_t *len, mode_type mode)
{
  switch (mode) {
  case GSI:
    return gsi_recv(fd, beginning, buf, len, 0);
    break;

  case TLS:
    return tls_recv(fd, beginning, buf, len, 0);
    break;

  case SSL2:
    return ssl2_recv(fd, beginning, buf, len, 0);
    break;

  case SSL_GLOBUS:
    return ssl_globus_recv(fd, beginning, buf, len, 0);
    break;

  default:
    return -1;
    break;
  }
}
