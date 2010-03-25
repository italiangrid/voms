/*********************************************************************
 *
 * Authors: Vincenzo Ciaschini - Vincenzo.Ciaschini@cnaf.infn.it 
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

#define _GNU_SOURCE
#include <expat.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "listfunc.h"
#include "errortype.h"
#include "xml.h"

#include <openssl/bio.h>
#include <openssl/evp.h>

static char trans[] = "abcdefghijklmnopqrstuvwxyz"
                      "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                      "0123456789[]";

static char trans2[128] = { 0,   0,  0,  0,  0,  0,  0,  0,
			    0,   0,  0,  0,  0,  0,  0,  0,
			    0,   0,  0,  0,  0,  0,  0,  0,
			    0,   0,  0,  0,  0,  0,  0,  0,
			    0,   0,  0,  0,  0,  0,  0,  0,
			    0,   0,  0,  0,  0,  0,  0,  0,
			    52, 53, 54, 55, 56, 57, 58, 59,
			    60, 61,  0,  0,  0,  0,  0,  0,
			    0,  26, 27, 28, 29, 30, 31, 32,
			    33, 34, 35, 36, 37, 38, 39, 40,
			    41, 42, 43, 44, 45, 46, 47, 48,
			    49, 50, 51, 62,  0, 63,  0,  0,
			    0,   0,  1,  2,  3,  4,  5,  6,
			    7,   8,  9, 10, 11, 12, 13, 14,
			    15, 16, 17, 18, 19, 20, 21, 22,
			    23, 24, 25,  0,  0,  0,  0,  0};
		     
static char *MyEncode(const char *data, int size, int *j);
static char *MyDecode(const char *data, int size, int *j);

static char *base64Encode(const char *data, int size, int *j)
{
  BIO *in = NULL;
  BIO *b64 = NULL;
  int len = 0;
  char *buffer = NULL;

  in  = BIO_new(BIO_s_mem());
  b64 = BIO_new(BIO_f_base64());
  if (!in || !b64)
    goto err;

  b64 = BIO_push(b64, in);

  BIO_write(b64, data, size);
  BIO_flush(b64);

  *j = len = BIO_pending(in);

  buffer = (char *)malloc(len);
  if (!buffer)
    goto err;

  if (BIO_read(in, buffer, len) != len) {
    free(buffer);
    buffer = NULL;
    goto err;
  }

 err:

  BIO_free(b64);
  BIO_free(in);
  return buffer;
}

static char *base64Decode(const char *data, int size, int *j)
{
  BIO *b64 = NULL;
  BIO *in = NULL;

  char *buffer = (char *)malloc(size);
  if (!buffer)
    return NULL;

  memset(buffer, 0, size);

  b64 = BIO_new(BIO_f_base64());
  in = BIO_new_mem_buf((char*)data, size);
  in = BIO_push(b64, in);

  *j = BIO_read(in, buffer, size);

  BIO_free_all(in);

  return buffer;
}

char *Decode(const char *data, int size, int *j)
{
  int i = 0;

  while (i < size)
    if (data[i++] == '\n')
      return base64Decode(data, size, j);

  return MyDecode(data, size, j);
}

static char *MyEncode(const char *data, int size, int *j)
{
  int bit = 0;
  int i   = 0;
  char *res;

  if (!data || !size) {
    *j = 0;
    return NULL;
  }

  if ((res = (char *)calloc(1, (size*4)/3+2))) {
    *j = 0;

    while (i < size) {
      char c = data[i];
      char c2 = ((i < (size-1)) ? data[i+1] : 0);
      switch (bit) {
      case 0:
        res[*j] = (c & 0xfc) >> 2;
        bit=2;
        break;
      case 2:
        res[*j] = ((c & 0x03) << 4) |  ((c2 & 0xf0) >> 4);
        bit=4;
        i++;
        break;
      case 4:
        res[*j] = ((c & 0x0f) << 2) | ((c2 & 0xc0) >> 6);
        bit=6;
        i++;
        break;
      case 6:
        res[*j] = c & 0x3f;
        bit=0;
        i++;
        break;
      default:
        free(res);
        return NULL;
        break;
      }
      res[*j] = trans[(int)res[*j]];
      (*j)++;
    }

    res[*j]='\0';
    return res;
  }
  return NULL;
}

static char *MyDecode(const char *data, int size, int *n)
{
  int bit = 0;
  int i = 0;
  char *res;

  if (!data || !size) return NULL;

  if ((res = (char *)calloc(1, (size*3)/4 + 2))) {
    *n = 0;

    while (i < size) {
      char c  = trans2[(int)data[i]];
      char c2 = (((i+1) < size) ? trans2[(int)data[i+1]] : 0);

      switch(bit) {
      case 0:
        res[*n] = ((c & 0x3f) << 2) | ((c2 & 0x30) >> 4);
        if ((i+1) < size)
          (*n)++;
        bit=4;
        i++;
        break;
      case 4:
        res[*n] = ((c & 0x0f) << 4) | ((c2 & 0x3c) >> 2);
        if ((i+1) < size)
          (*n)++;
        bit=2;
        i++;
        break;
      case 2:
        res[*n] = ((c & 0x03) << 6) | (c2 & 0x3f);
        if ((i+1) < size)
          (*n)++;
        
        i += 2;
        bit = 0;
        break;
      }
    }

    return res;
  }
  return NULL;
}

static void startans(void *userdata, UNUSED(const char *name), UNUSED(const char **attrs))
{
  struct ans *a = (struct ans *)userdata;

  if (a->depth == 4)
    a->error = 1;
  else {
    a->depth++;
    a->value = "";
  }
}

static void startreq(void *userdata, UNUSED(const char *name), UNUSED(const char **attrs))
{
  struct req *d = (struct req *)userdata;

  if (!d || d->error)
    return;

  if (d->depth == 2) {
    d->error = 1;
    return;
  }

  d->depth++;
  d->value = "";
}

static void endreq(void *userdata, const char *name)
{
  struct req *d = (struct req *)userdata;

  if (!d || d->error)
    return;

  if (d->depth == 0) {
    d->error = 1;
    return;
  }

  d->depth--;
  if (strcmp(name, "order") == 0)
    d->r->order = d->value;
  else if (strcmp(name, "targets") == 0)
    d->r->targets = d->value;
  else if (strcmp(name, "command") == 0)
    d->r->command.push_back(d->value);
  else if (strcmp(name, "lifetime") == 0)
    d->r->lifetime = atoi(d->value.c_str());
  else if (strcmp(name, "base64") == 0)
    d->r->base64 = 1;
  else if (strcmp(name, "version") == 0)
    d->r->version = atoi(d->value.c_str());
  d->value="";
}

static void endans(void *userdata, const char *name)
{
  struct ans *a = (struct ans *)userdata;

  if (!a)
    return;

  if(a->error || !a->depth) {
    a->error = 1;
    return;
  }

  a->depth--;
  if (!strcmp(name,"ac")) {
    a->a->ac = Decode(a->value);
    if (a->a->ac.empty())
      a->error=1;
  }
  else if (!strcmp(name, "bitstr")) {
    a->a->data = Decode(a->value);
    if (a->a->data.empty())
      a->error=1;
  }
  else if (!strcmp(name, "error")) {
    struct errorp e;
    e->num     = a->num;
    e->message = a->message;
    a->a->errs.push_back(e);
  }
  else if ((!strcmp(name, "number")) && 
           (a->depth == 3)) {
    a->num = atoi(a->value.c_str());
  }
  else if ((!strcmp(name, "message")) && 
           (a->depth == 3)) {
    a->message = a->value;
  }
  else if ((!strcmp(name, "version"))) {
    a->a->version = atoi(a->value.c_str());
  }
  a->value = "";
}
      
static void handlerreq(void *userdata, const char *s, int len)
{
  struct req *d = (struct req *)userdata;

  if (!d || d->error)
    return;

  d->value = std::string(s, len);

  if (d->value.empty() && len)
    d->error = 1;
}

static void handlerans(void *userdata, const char *s, int len)
{
  struct ans *a = (struct ans *)userdata;

  if (!a || a->error)
    return;

  if (a->value.empty())
    a->value = std::string(s, len);
  else {
    a->value += std::string(s, len);
  }

  if (a->value.empty() && len)
    a->error = 1;
}

int XMLDecodeReq(const char *message, struct req *d)
{
  XML_Parser p = XML_ParserCreate(NULL);
  int res;
  d->command = NULL;
  d->order = d->targets = d->value = NULL;
  d->error = d->depth = 0;
  d->lifetime = -1;
  d->version = d->base64 = 0;

  XML_SetUserData(p, d);
  XML_SetElementHandler(p,startreq,endreq);
  XML_SetCharacterDataHandler(p,handlerreq);
  res = XML_Parse(p, message, strlen(message), 1);
  XML_ParserFree(p);
  free(d->value);
  return res;
}

int XMLDecodeAns(const char *message, struct ans *d)
{
  XML_Parser p = XML_ParserCreate(NULL);
  int res;

  d->depth = d->error = d->datalen = d->aclen = 0;
  d->data  = d->ac = d->value = NULL;
  d->list  = NULL;
  d->err   = NULL;
  d->version = 0;

  XML_SetUserData(p, d);
  XML_SetElementHandler(p,startans,endans);
  XML_SetCharacterDataHandler(p,handlerans);
  res = XML_Parse(p, message, strlen(message), 1);
  XML_ParserFree(p);
  return res;
}

#if 0
int main(int argc, char *argv[])
{
  struct req d;

  d.depth = d.error = 0;

  return XMLDecode("<?xml version=\"1.0\" encoding = \"US-ASCII\"?><voms>"
		   "<command>A</command><order>G1:R1,G2:R2,G3,G4:R3</order>"
		   "<lifetime>5000</lifetime><target>targ</target></voms>", &d);
}
#endif
