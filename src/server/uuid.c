/*********************************************************************
 *
 * Authors: Vincenzo Ciaschini - Vincenzo.Ciaschini@cnaf.infn.it 
 *          Valerio Venturi    - Valerio.Venturi@cnaf.infn.it
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
  if (have_urandom) {
    int fd = open("/dev/urandom", O_RDONLY);
    int hasread = 0;
    int readb = 0;
    do {
      readb = read(fd, uuid+hasread, 16 - hasread);
      hasread += readb;
    } while (readb > 0 && hasread <16);
    close(fd);
  }
  else {
    int i;

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
