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

#include "listfunc.h"
}

#include <string>
#include <vector>
#include <sstream>

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
  std::ostringstream os;

  char const *file;
  int line;
  char const *data;
  int flags;
  unsigned long code = ERR_get_error_line_data(&file, &line, &data, &flags);
  while (code)
  {
    std::size_t const buf_size = 256;
    char buf[buf_size];
    ERR_error_string_n(code, buf, buf_size);
    os << file << ':' << line << ':'
       << buf << (data && (flags & ERR_TXT_STRING) ? data : "") << '\n';
    code = ERR_get_error_line_data(&file, &line, &data, &flags);
  }

  return os.str();
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

extern "C" {
int hex2num(char c)
{
  if (isdigit(c))
    return c - '0';
  else {
    char d = tolower(c);

    if (d >= 'a' && d <= 'f')
      return d - 'a' + 10;

    return 0;
  }
}

}
// convert vector of strings to char**
char **vectoarray(std::vector<std::string>& vector)
{
  char **array = (char**)calloc(vector.size() + 1, sizeof(char*));

  if (array) {
    int j = 0;

    std::vector<std::string>::const_iterator end = vector.end();
    for (std::vector<std::string>::const_iterator i = vector.begin(); i != end; ++i) {
      array[j] = strdup((*i).c_str());
      if (!array[j]) {
        listfree(array, free);
        return NULL;
      }
      j++;
    }
  }

  return array;
}
