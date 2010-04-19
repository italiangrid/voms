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

extern "C" {
#include "replace.h"

#include <stdio.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <time.h>
#include <netinet/in.h>
#include <netdb.h>
#include <string.h>

#include <openssl/buffer.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
}

#include <string>

#include "data.h"

/*
 * Encapsulates select behaviour
 *
 * Returns:
 *     > 0 : Ready to read or write.
 *     = 0 : timeout reached.
 *     < 0 : error.
 */
int do_select(int fd, time_t starttime, int timeout, int wanted)
{
  fd_set rset;
  fd_set wset;

  FD_ZERO(&rset);
  FD_ZERO(&wset);

  if (wanted == 0 || wanted == SSL_ERROR_WANT_READ)
    FD_SET(fd, &rset);
  if (wanted == 0 || wanted == SSL_ERROR_WANT_WRITE)
    FD_SET(fd, &wset);

  int ret = 0;

  if (timeout != -1) {
    timeval endtime;

    time_t curtime = time(NULL);

    if (curtime - starttime >= timeout)
      return 0;

    endtime.tv_sec = timeout - (curtime - starttime);
    endtime.tv_usec = 0;

    ret = select(fd+1, &rset, &wset, NULL, &endtime);
  }
  else {
    ret = select(fd+1, &rset, &wset, NULL, NULL);
  }

  if (ret == 0)
    return 0;

  if ((wanted == SSL_ERROR_WANT_READ && !FD_ISSET(fd, &rset)) ||
      (wanted == SSL_ERROR_WANT_WRITE && !FD_ISSET(fd, &wset)))
    return -1;

  if (ret < 0 && (!FD_ISSET(fd, &rset) || !FD_ISSET(fd, &wset)))
    return 1;

  return ret;
}


#define TEST_SELECT(ret, ret2, timeout, curtime, starttime, errorcode) \
  ((ret) > 0 && ((ret2) <= 0 && (((timeout) == -1) ||                  \
                                 (((timeout) != -1) &&                 \
                                  ((curtime) - (starttime)) < (timeout))) && \
                 ((errorcode) == SSL_ERROR_WANT_READ ||                 \
                  (errorcode) == SSL_ERROR_WANT_WRITE)))

bool do_connect(SSL *ssl, int fd, int timeout, std::string& error)
{
  time_t starttime, curtime;
  int ret = -1, ret2 = -1;
  long errorcode = 0;
  int expected = 0;

  curtime = starttime = time(NULL);

  do {
    ret = do_select(fd, starttime, timeout, expected);
    if (ret > 0) {
      ret2 = SSL_connect(ssl);
      curtime = time(NULL);
      expected = errorcode = SSL_get_error(ssl, ret2);
    }
  } while (TEST_SELECT(ret, ret2, timeout, curtime, starttime, errorcode));


  if (ret2 <= 0 || ret <= 0) {
    if (timeout != -1 && (curtime - starttime <= timeout))
      error = "Connection stuck during handshake: timeout reached.";
    else
      error = "Error during SSL handshake:" + OpenSSLError(true);
    return false;
  }

  return true;
}



bool do_write(SSL *ssl, int timeout, const std::string& text, std::string &error)
{
  errno = 0;

  if (!ssl) {
    error = "No connection established";
    return false;
  }

  ERR_clear_error();

  int ret = 0, nwritten=0;

  const char *str = text.c_str();

  int fd = BIO_get_fd(SSL_get_rbio(ssl), NULL);
  time_t starttime, curtime;

  bool do_continue = false;
  int expected = 0;

  curtime = starttime = time(NULL);

  do {
    ret = do_select(fd, starttime, timeout, expected);

    do_continue = false;
    if (ret > 0) {
      int v;
      errno = 0;
      ret = SSL_write(ssl, str + nwritten, strlen(str) - nwritten);
      curtime = time(NULL);
      v = SSL_get_error(ssl, ret);

      switch (v) {
      case SSL_ERROR_NONE:
        nwritten += ret;
        if ((size_t)nwritten == strlen(str))
          do_continue = false;
        else
          do_continue = true;
        break;

      case SSL_ERROR_WANT_READ:
        expected = SSL_ERROR_WANT_READ;
        ret = 1;
        do_continue = true;
        break;
        
      case SSL_ERROR_WANT_WRITE:
        expected = SSL_ERROR_WANT_WRITE;
        ret = 1;
        do_continue = true;
        break;

      default:
        do_continue = false;
      }
    }
  } while (ret <= 0 && do_continue);
           
  if (ret <=0) {
    if (timeout != -1 && (curtime - starttime <= timeout))
      error ="Connection stuck during write: timeout reached.";
    else
      error = "Error during SSL write:" + OpenSSLError(true);
    return false;
  }

  return true;
}

bool do_read(SSL *ssl, int timeout, std::string& output)
{
  if (!ssl) {
    output = "No connection established";
    return false;
  }

  ERR_clear_error();

  int ret = -1, ret2 = -1;

  int bufsize=16384;

  char *buffer = (char *)OPENSSL_malloc(bufsize);

  int fd = BIO_get_fd(SSL_get_rbio(ssl), NULL);
  time_t starttime, curtime;

  int error = 0;
  long int expected = 0;

  starttime = time(NULL);

  do {
    ret = do_select(fd, starttime, timeout, expected);
    curtime = time(NULL);

    if (ret > 0) {
      ret2 = SSL_read(ssl, buffer, bufsize);

      if (ret2 <= 0) {
        expected = error = SSL_get_error(ssl, ret2);
      }        
    }
  } while (TEST_SELECT(ret, ret2, timeout, curtime, starttime, expected)); 
            
  if (ret <= 0 || ret2 <= 0) {
    if (timeout != -1 && (curtime - starttime <= timeout))
      output = "Connection stuck during read: timeout reached.";
    else
      output = "Error during SSL read:" + OpenSSLError(true);
    OPENSSL_free(buffer);
    return false;
  }

  output = std::string(buffer, ret2);
  OPENSSL_free(buffer);
  return true;

}
