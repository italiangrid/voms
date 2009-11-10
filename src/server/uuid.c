/*********************************************************************
 *
 * Authors: Vincenzo Ciaschini - Vincenzo.Ciaschini@cnaf.infn.it 
 *          Valerio Venturi    - Valerio.Venturi@cnaf.infn.it
 *
 * Copyright (c) 2002-2009 INFN-CNAF on behalf of the EU DataGrid
 * and EGEE I, II and III
 * For license conditions see LICENSE file or
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 *
 * Parts of this code may be based upon or even include verbatim pieces,
 * originally written by other people, in which case the original header
 * follows.
 *
 *********************************************************************/
#include "config.h"
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

static int have_urandom = 0;

void initialize_uuid_generator()
{
  int fd = open("/dev/urandom", O_RDONLY);
  if (fd == -1) {
    srandom(time(NULL));
    have_urandom = 0;
  }
  else {
    close(fd);
    have_urandom = 1;
  }
}

void generate_uuid(unsigned char uuid[16])
{
  int i = 0;

  int fd = -1;

  if (have_urandom) {
    fd = open("/dev/urandom", O_RDONLY);
    int hasread = read(fd, uuid, 16);
    close(fd);
  }
  else {
    for (i =0 ; i < 16; i ++)
      uuid[i] = (random() & 0x000ff000) >> 12;
  }

  /* Set highest bits to 01 (point 1 of RFC 4122 4.4 */
  uuid[8] &= 0x3f;
  uuid[8] |= 0x80;

  /* Set the four highest bits to 0100 (point 2 of RFC 4122 4.4 */
  uuid[6] &= 0x0f;
  uuid[6] |= 0x40;
}
