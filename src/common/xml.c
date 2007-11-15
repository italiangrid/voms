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
  BIO *in = NULL;
  BIO *b64 = NULL;
  int len = 0;
  char *buffer = NULL;
  int read = 0;

  in  = BIO_new(BIO_s_mem());
  b64 = BIO_new(BIO_f_base64());
  if (!in || !b64)
    goto err;

  b64 = BIO_push(b64, in);

  BIO_write(in, data, size);
  BIO_flush(in);

  len = BIO_pending(b64);

  buffer = (char *)malloc(len);
  if (!buffer)
    goto err;

  *j = read = BIO_read(b64, buffer, len);

  if (read <= 0) {
    free(buffer);
    buffer = NULL;
    goto err;
  }

 err:

  BIO_free(b64);
  BIO_free(in);
  return buffer;
}

char *Encode(const char *data, int size, int *j, int base64)
{
  if (base64)
    return base64Encode(data, size, j);
  else
    return MyEncode(data, size, j);
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

char *XMLEncodeReq(const char *command, const char *order, const char *targets,
                  int lifetime)
{
  char *res;
  int size;
  char str[15];
  const char *tmp;
  int count = 0;

  if (!command)
    return NULL;

  size = strlen(command) + (order ? strlen(order) : 0) +
    (targets ? strlen(targets) : 0) + 167;

  /* count the number of commands -1*/
  tmp = command;

  while (tmp = strchr(tmp, ','))  {
    count ++;
    tmp++;
  }
    
  size += (count * 19);

  if ((res = (char *)malloc(size))) {
    const char * prev = command;
    const char *next = prev;

    strcpy(res, "<?xml version=\"1.0\" encoding = \"US-ASCII\"?><voms>");

    while(next != 0)
    { 
      next = strchr(prev, ',');

      strcat(res, "<command>");
      strncat(res, prev, (next ? next - prev : command + strlen(command) - prev));
      strcat(res, "</command>");

      prev = next + 1;
    }

    if (order && strlen(order)) {
      strcat(res, "<order>");
      strcat(res, order);
      strcat(res, "</order>");
    }

    if (targets && strlen(targets)) {
      strcat(res, "<targets>");
      strcat(res, targets);
      strcat(res, "</targets>");
    }

    strcat(res,"<base64>1</base64>");

    sprintf(str, "%d", lifetime);
    strcat(res, "<lifetime>");
    strcat(res, str);
    strcat(res, "</lifetime></voms>");


    return res;
  }
  return NULL;
}

char *XMLEncodeAns(struct error **wande, const char *ac, int lenac,
                   const char *data, int lendata, int base64)
{
  char *res;
  int size;
  char str[15];
  char *codeddata;
  char *codedac;
  int newdata;
  int newac;

  if (!ac)
    return NULL;

  if (!ac)  lenac  = 0;

  codedac   = Encode(ac, lenac, &newac, base64);
  codeddata = Encode(data, lendata, &newdata, base64);

  if ((!codedac && ac) && (!codeddata && data)) {
    free(codedac);
    free(codeddata);
    return NULL;
  }

  size = newac + newdata + 95;

  if (wande) {
    struct error **tmp = wande;
    size += 15;
    while (*tmp) {
      size += strlen((*tmp)->message) + 64;
      tmp++;
    }
  }

  if ((res = (char *)malloc(size))) {
    strcpy(res, "<?xml version=\"1.0\" encoding = \"US-ASCII\"?><vomsans>");

    if (wande) {
      struct error **tmp = wande;
      strcat(res, "<error>");
      while (*tmp) {
        strcat(res, "<item><number>");
        sprintf(str, "%d", (*tmp)->num);
        strcat(res, str);
        strcat(res, "</number><message>");
        strcat(res, (*tmp)->message);
        strcat(res, "</message></item>");
        tmp++;
      }
      strcat(res, "</error>");
    }

    if (codeddata) {
      strcat(res, "<bitstr>");
      strncat(res, codeddata, newdata);
      strcat(res, "</bitstr>");
      free(codeddata);
    }

    if (codedac) {
      strcat(res, "<ac>");
      strncat(res, codedac, newac);
      strcat(res, "</ac>");
      free(codedac);
    }
    strcat(res, "</vomsans>");

    return res;
  }
  return NULL;
}

static void  startans(void *userdata, const char *name, const char **attrs)
{
  struct ans *a = (struct ans *)userdata;

  if (a->depth == 4)
    a->error = 1;
  else {
    a->depth++;
    a->value = NULL;
  }
}

static void  startreq(void *userdata, const char *name, const char **attrs)
{
  struct req *d = (struct req *)userdata;
  if (!d || d->error)
    return;

  if (d->depth == 2) {
    d->error = 1;
    return;
  }

  d->depth++;
  d->value = NULL;
}

static void  endreq(void *userdata, const char *name)
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
    d->order = d->value;
  else if (strcmp(name, "target") == 0)
    d->targets = d->value;
  else if (strcmp(name, "command") == 0)
  {
    d->command = listadd(d->command, d->value, sizeof(char *));
  }  
  else if (strcmp(name, "lifetime") == 0)
    d->lifetime = atoi(d->value);
  else if (strcmp(name, "base64") == 0)
    d->base64 = 1;
  d->value=NULL;
}

static void  endans(void *userdata, const char *name)
{
  struct ans *a = (struct ans *)userdata;
  struct error *e;

  if (!a)
    return;

  if(a->error || !a->depth) {
    a->error = 1;
    return;
  }

  a->depth--;
  if (!strcmp(name,"ac")) {
    int size;
    char *dec = Decode(a->value, strlen(a->value), &size);
    free(a->value);
    if (dec) {
      a->ac = dec;
      a->aclen = size;
    }
    else
      a->error=1;
  }
  else if (!strcmp(name, "bitstr")) {
    int size;
    char *dec = Decode(a->value, strlen(a->value), &size);
    free(a->value);
    if (dec) {
      a->data = dec;
      a->datalen = size;
    }
    else
      a->error=1;
  }
  else if (!strcmp(name, "error")) {
    struct error **tmp;
    tmp = (struct error **)listadd((char **)(a->list), (char *)(a->err), sizeof(struct error *));
/*     free(a->err->message); */
/*     free_error(a->err); */
    free(a->value);
    a->err = NULL;
    if (tmp)
      a->list = tmp;
    else {
      listfree((char **)tmp, (void (*)(void *))free_error);
      a->error=1;
    }
  }
  else if ((!strcmp(name, "number")) && 
	   (a->depth == 3) && 
	   (e = (struct error *)malloc(sizeof(struct error)))) {
    if (a->err)
      free(e);
    else
      a->err = e;
    a->err->num = atoi(a->value);
    free(a->value);
  }
  else if ((!strcmp(name, "message")) && 
	   (a->depth == 3) && 
	   (e = (struct error *)malloc(sizeof(struct error)))) {
    if (a->err)
      free(e);
    else
      a->err = e;
    a->err->message = strdup(a->value);
    free(a->value);
  }
  a->value = NULL;
}
      
static void  handlerreq(void *userdata, const char *s, int len)
{
  struct req *d = (struct req *)userdata;

  if (!d || d->error)
    return;

  d->value = strndup(s, len);
  if (!d->value && len)
    d->error = 1;
}

static void  handlerans(void *userdata, const char *s, int len)
{
  struct ans *a = (struct ans *)userdata;

  if (!a || a->error)
    return;

  if (!a->value)
    a->value = strndup(s, len);
  else {
    a->value = (char*)realloc(a->value, strlen(a->value) + len + 1);

    if (a->value)
      a->value = strncat(a->value, s, len);
    else if (len)
      a->error = 1;
  }

  if (!a->value && len)
    a->error = 1;
}

int XMLDecodeReq(const char *message, struct req *d)
{
  XML_Parser p = XML_ParserCreate(NULL);
  int res;
  d->command = NULL;
  d->order = d->targets = d->value = NULL;
  d->error = d->depth = d->n = 0;
  d->lifetime = -1;
  
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
