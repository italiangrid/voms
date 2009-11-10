
#include "voms_apic.h"
#include <stdlib.h>
#include <stdio.h>
#include <sys/time.h>

#include <openssl/buffer.h>
#include <openssl/crypto.h>
#include <openssl/objects.h>
#include <openssl/asn1.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/rsa.h>

static time_t stillvalid(ASN1_TIME *ctm);
static ASN1_TIME *convtime(char *data, int len);

int main(int argc, char *argv[]) {
  struct vomsdata *vd = VOMS_Init(NULL, NULL);
  int error = 0;

  char * command;

  command="G/voms1";

  if (vd) {

    struct contactdata **vomses = VOMS_FindByAlias(vd, "voms1", NULL, NULL, &error);

    if (vomses[0]) {
      VOMS_SetLifetime(10*60, vd, &error);
      if (VOMS_Contact(vomses[0]->host, vomses[0]->port, vomses[0]->contact,
                       command, vd, &error)) {
        struct voms *voms = VOMS_DefaultData(vd, &error);
	int life1 = stillvalid(convtime(voms->date1, strlen(voms->date1)));
	int life2 = stillvalid(convtime(voms->date2, strlen(voms->date2)));

        if (voms) {
	  printf("validity: %ld\n", life2 - life1);
          exit(0);
        }
      }
    }
  }

  fprintf(stderr, "Error Message1: %s\n", VOMS_ErrorMessage(vd, error, NULL, 0));
  exit (1);
}

static ASN1_TIME *
convtime(char *data, int len)
{
  ASN1_TIME *t= ASN1_TIME_new();

  t->data   = data;
  t->length = len;
  switch(t->length) {
  case 10:
    t->type = V_ASN1_UTCTIME;
    break;
  case 15:
    t->type = V_ASN1_GENERALIZEDTIME;
    break;
  default:
    ASN1_TIME_free(t);
    return NULL;
  }
  return t;
}

static time_t stillvalid(ASN1_TIME *ctm)
{
  char     *str;
  time_t    offset;
  time_t    newtime;
  char      buff1[32];
  char     *p;
  int       i;
  struct tm tm;
  int       size = 0;

  switch (ctm->type) {
  case V_ASN1_UTCTIME:
    size=10;
    break;
  case V_ASN1_GENERALIZEDTIME:
    size=12;
    break;
  }
  p = buff1;
  i = ctm->length;
  str = (char *)ctm->data;
  if ((i < 11) || (i > 17)) {
    newtime = 0;
  }
  memcpy(p,str,size);
  p += size;
  str += size;

  if ((*str == 'Z') || (*str == '-') || (*str == '+')) {
    *(p++)='0'; *(p++)='0';
  }
  else {
    *(p++)= *(str++); *(p++)= *(str++);
  }
  *(p++)='Z';
  *(p++)='\0';

  if (*str == 'Z') {
    offset=0;
  }
  else {
    if ((*str != '+') && (str[5] != '-')) {
      newtime = 0;
    }
    offset=((str[1]-'0')*10+(str[2]-'0'))*60;
    offset+=(str[3]-'0')*10+(str[4]-'0');
    if (*str == '-') {
      offset=-offset;
    }
  }

  tm.tm_isdst = 0;
  int index = 0;
  if (ctm->type == V_ASN1_UTCTIME) {
    tm.tm_year  = (buff1[index++]-'0')*10;
    tm.tm_year += (buff1[index++]-'0');
  }
  else {
    tm.tm_year  = (buff1[index++]-'0')*1000;
    tm.tm_year += (buff1[index++]-'0')*100;
    tm.tm_year += (buff1[index++]-'0')*10;
    tm.tm_year += (buff1[index++]-'0');
  }

  if (tm.tm_year < 70) {
    tm.tm_year+=100;
  }

  if (tm.tm_year > 1900) {
    tm.tm_year -= 1900;
  }

  tm.tm_mon   = (buff1[index++]-'0')*10;
  tm.tm_mon  += (buff1[index++]-'0')-1;
  tm.tm_mday  = (buff1[index++]-'0')*10;
  tm.tm_mday += (buff1[index++]-'0');
  tm.tm_hour  = (buff1[index++]-'0')*10;
  tm.tm_hour += (buff1[index++]-'0');
  tm.tm_min   = (buff1[index++]-'0')*10;
  tm.tm_min  += (buff1[index++]-'0');
  tm.tm_sec   = (buff1[index++]-'0')*10;
  tm.tm_sec  += (buff1[index++]-'0');

  /*
   * mktime assumes local time, so subtract off
   * timezone, which is seconds off of GMT. first
   * we need to initialize it with tzset() however.
   */

  tzset();

  /*
   * for this usage, timezone does not matter.
   */
  newtime = (mktime(&tm) + offset*60*60);

  return newtime;
}
