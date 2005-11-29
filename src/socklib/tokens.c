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
    while(num_read < 4)
    {
      if (sockalarmed)
        alarm(sockalarmed);

      n_read = recv(fd,token_length_buffer + num_read, 4 - num_read,0);
      alarm(0);

      alrm = alarmed; 
      alarmed = 0; 

      if (alrm)
        return -1;

      if(n_read < 0) {
        if(errno == EINTR && !alrm)
          continue;
        else
          return -1;
      }
      else if (n_read == 0)
        return GLOBUS_GSS_ASSIST_TOKEN_EOF;
      else
        num_read += n_read;
    }
    num_read = 0;
    /* decode the token length from network byte order: 4 byte, big endian */

    *token_length  = (((size_t) token_length_buffer[0]) << 24) & 0xffffffff;
    *token_length |= (((size_t) token_length_buffer[1]) << 16) & 0xffffffff;
    *token_length |= (((size_t) token_length_buffer[2]) <<  8) & 0xffffffff;
    *token_length |= (((size_t) token_length_buffer[3])      ) & 0xffffffff;

    if(*token_length > 1<<24) {
      /* token too large */
      return -1;
    }

    /* allocate space for the token */

    *((void **)token) = (void *) malloc(*token_length);

    if (*token == NULL) {
      return -1;
    }

    /* receive the token */

    num_read = 0;
    while(num_read < *token_length) {
      if (sockalarmed)
        alarm(sockalarmed); 
      n_read = recv(fd, ((u_char *) (*token)) + num_read,(*token_length) - num_read,0);
      alarm(0);

      alrm = alarmed; 
      alarmed = 0; 

      if (alrm)
        return -1;

      if(n_read < 0) {
        if(errno == EINTR && !alrm)
          continue;
        else
          return -1;
      }
      else {
        if(n_read == 0)
          return -1; 
      }
	    num_read += n_read;
    }

    return 0;
}











