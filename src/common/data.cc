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
#include "config.h"

extern "C" {
#include <stdio.h>
#include <stdarg.h>
#include <ctype.h>
#include <string.h>
#include <time.h>
#include <limits.h>
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

bool 
acceptable(std::string s)
{
  return acceptable(s.c_str());
}

std::string
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

  sprintf(val, "%d\0", i);

  s = val;

  return s;
}
