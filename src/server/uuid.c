#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <stdio.h>

void initialize_uuid_generator()
{
  int max_value;
  int num_bits = 0;

  srandom(time(NULL));

}

void generate_uuid(unsigned char uuid[16])
{
  int i = 0;

  int fd = -1;

  fd = open("/dev/urandom", 0);

  if (fd == -1) {
    /* generate all random data */

    for (i =0 ; i < 16; i ++)
      uuid[i] = (random() & 0x000ff000) >> 12;
  }
  else {
    /* read from /dev/urandom */
    read(fd, uuid, 16);
  }

  /* Set highest bits to 01 (point 1 of RFC 4122 4.4 */
  uuid[8] &= 0x3f;
  uuid[8] |= 0x80;

  /* Set the four highest bits to 0100 (point 2 of RFC 4122 4.4 */
  uuid[6] &= 0x0f;
  uuid[6] |= 0x40;
}
