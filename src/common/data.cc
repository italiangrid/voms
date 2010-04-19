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
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdarg.h>
#include <ctype.h>
#include <string.h>
#include <time.h>
#include <limits.h>
#include <unistd.h>

#include <openssl/err.h>
#include <openssl/ssl.h>
}

#include <string>
/*
 * Function:
 *   filter(c)
 *
 * Description:
 *   This function verifies if character 'c' is suitable to be included as
 *   user input into an SQL query.
 *
 * Parameters:
 *   'c' - The character to test.
 *
 * Result:
 *   A boolean indicating success or failure.
 *
 * Note:
 *   This function could have been implemented more easily using the
 *   isalnum() and the like. The problem with those functions is that
 *   they are subject to the current LOCALE, and so there is no way to
 *   actually be sure about the characters tested.  This way should be
 *   free of that problem.
 */
static bool
filter(char c)
{
  switch (c) {
  case '0': case '1': case '2': case '3': case '4': case '5': case '6':
  case '7': case '8': case '9': case '_': case 'A': case 'B': case 'C':
  case 'D': case 'E': case 'F': case 'G': case 'H': case 'I': case 'J':
  case 'K': case 'L': case 'M': case 'N': case 'O': case 'P': case 'Q':
  case 'R': case 'S': case 'T': case 'U': case 'V': case 'W': case 'X':
  case 'Y': case 'Z': case 'a': case 'b': case 'c': case 'd': case 'e':
  case 'f': case 'g': case 'h': case 'i': case 'j': case 'k': case 'l':
  case 'm': case 'n': case 'o': case 'p': case 'q': case 'r': case 's':
  case 't': case 'u': case 'v': case 'w': case 'x': case 'y': case 'z':
  case '/': case '-': case '.':
    return true;
  default:
    return false;
  }
}

/*
 * Function:
 *   acceptable(str)
 *
 * Description:
 *   This function tests a whole string for suitability for insertion
 *   into an SQL query.
 *
 * Parameters:
 *   'str' - The string to be tested. Note that the NULL string always
 *           tests true.
 *
 * Result:
 *   A boolean indicating success or failure.
 */
bool
acceptable(const char *str)
{
  if (str) {
    while (*str) {
      if (!filter(*str))
        return false;
      str++;
    }
  }
  return true;
}

char *
timestamp(void)
{
    time_t clock;
    struct tm *tmp;

    time(&clock);
    tmp = localtime(&clock);
    return asctime(tmp);
}

std::string 
stringify(int i, std::string &s)
{
  // Gets an integer' size in chars + '\0'
#define INTSIZE (((sizeof(int)*CHAR_BIT)/3)+2)
  static char val[INTSIZE];

  memset(val, 0, INTSIZE);
#undef INTSIZE

  sprintf(val, "%d", i);

  s = val;

  return s;
}

std::string OpenSSLError(bool debug) 
{
  unsigned long l;
  char buf[256];
#if SSLEAY_VERSION_NUMBER  >= 0x00904100L
  const char *file;
#else
  char *file;
#endif
  char *dat;
  int line;

  std::string outstring;
  char *msgstring = NULL;
    
  /* WIN32 does not have the ERR_get_error_line_data */ 
  /* exported, so simulate it till it is fixed */
  /* in SSLeay-0.9.0 */
  
  while ( ERR_peek_error() != 0 ) {
    
    int i;
    ERR_STATE *es;
      
    es = ERR_get_state();
    i = (es->bottom+1)%ERR_NUM_ERRORS;

    if (es->err_data[i] == NULL)
      dat = strdup("");
    else
      dat = strdup(es->err_data[i]);


    if (dat) {
      int code = 0;

      l = ERR_get_error_line(&file, &line);
      code = ERR_GET_REASON(l);

      switch (code) {
      case SSL_R_SSLV3_ALERT_CERTIFICATE_EXPIRED:
        outstring += "Either proxy or user certificate are expired.";
        break;

      default:
        if (debug) {
          std::string temp;
          
          outstring += std::string(ERR_error_string(l,buf)) + ":" +
            file + ":" + stringify(line, temp) + dat + "\n";
        }

        msgstring = (char*)ERR_reason_error_string(l);

        if (msgstring)
          outstring += std::string(msgstring) + dat +
            "\nFunction: " + ERR_func_error_string(l) + "\n";
        break;
      }
    }
    
    free(dat);
  }

  return outstring;
}

static char *readfile(const char *file, int *size)
{
  int fd = open(file,O_RDONLY);
  char *buffer = NULL;

  if (fd != -1) {
    struct stat filestats;

    if (!fstat(fd, &filestats)) {
      *size = filestats.st_size;

      buffer = (char *)malloc(*size);

      if (buffer) {
        int offset = 0;
        int ret = 0;

        do {
          ret = read(fd, buffer+offset, *size - offset);
          offset += ret;
        } while ( ret > 0);

        if (ret < 0) {
          free(buffer);
          buffer = NULL;
        }
      }
    }
    close(fd);
  }

  return buffer;
}

std::string readfile(std::string filename)
{
  int len = 0;
  char *buffer = NULL;
  std::string result = "";

  buffer = readfile(filename.c_str(), &len);

  if (buffer) {
    result = std::string(buffer, len);
    free(buffer);
  }

  return result;
}
