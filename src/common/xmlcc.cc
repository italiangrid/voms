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

#include "vomsxml.h"
#include "errors.h"

extern "C" {
#include <expat.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/bio.h>
#include <openssl/evp.h>

#include "doio.h"
static void startans(void *userdata, UNUSED(const char *name), UNUSED(const char **attrs));
static void startreq(void *userdata, UNUSED(const char *name), UNUSED(const char **attrs));
static void endreq(void *userdata, const char *name);
static void endans(void *userdata, const char *name);
static void handlerreq(void *userdata, const char *s, int len);
static void handlerans(void *userdata, const char *s, int len);
}

struct req {
  struct request *r;
  std::string value;
  int   error;
  int   depth;
};

struct ans {
  struct answer *a;
  std::string value;
  int error;
  int depth;
  int num;
  std::string message;
};


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

std::string Decode(const std::string data)
{
  int j = 0;
  char * tmp = NULL;

  if (data.find_first_of('\n') != std::string::npos)
    tmp = base64Decode(data.data(), data.size(), &j);
  else
    tmp = MyDecode(data.data(), data.size(), &j);

  if (tmp)
    return std::string(tmp, j);

  return "";
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

std::string XML_Req_Encode(const std::string &command, const std::string &order,
                          const std::string &targets, const int lifetime)
{
  std::string res = "<?xml version=\"1.0\" encoding = \"US-ASCII\"?><voms>";

  char *str = NULL;

  std::string::size_type begin = 0;
  std::string::size_type pos = 0;

  do {
    pos = command.find_first_of(',', begin);
    res += "<command>";
    if (pos != std::string::npos) {
      res += command.substr(begin, pos);
      begin = pos + 1;
    }
    else
      res += command.substr(begin);
    res += "</command>";
  } while (pos != std::string::npos);

  if (!order.empty())
    res += "<order>"+order+"</order>";

  if (!targets.empty())
    res += "<targets>"+targets+"</targets>";

  res += "<base64>1</base64><version>4</version>";

  str = snprintf_wrap("%d", lifetime);

  res += "<lifetime>"+std::string(str ? str : "")+"</lifetime></voms>";

  free(str);

  return res;
}

std::string XML_Ans_Encode(const std::string &ac, const std::vector<errorp> e, bool base64)
{
  return XML_Ans_Encode(ac, "", e, base64);
}

std::string Encode(std::string data, int base64)
{
  int j = 0;
  char *tmp = NULL;
  std::string result;

  if (base64)
    tmp = base64Encode(data.data(), data.size(), &j);
  else
    tmp = MyEncode(data.data(), data.size(), &j);

  if (tmp) {
    result = std::string(tmp, j);
    free(tmp);
  }

  return result;
}

std::string XML_Ans_Encode(const std::string &ac, const std::string &data, const std::vector<errorp> e, bool base64)
{
  char *str = NULL;

  if (ac.empty() && data.empty())
    return "";

  std::string codedac   = Encode(ac, base64);
  std::string codeddata = Encode(data, base64);

  if ((codedac.empty() && !ac.empty()) && (codeddata.empty() && !data.empty())) {
    return "";
  }

  std::string res="<?xml version=\"1.0\" encoding = \"US-ASCII\"?><vomsans><version>3</version>";

  if (!e.empty()) {
    res += "<error>";

    for (std::vector<errorp>::const_iterator i = e.begin(); i != e.end(); i++) {
      res +="<item><number>";
      str = snprintf_wrap("%d", (*i).num);
      res += std::string(str ? str : "");
      free(str);
      res += "</number><message>" + (*i).message + "</message></item>";
    }
    res +="</error>";
  }

  if (!codeddata.empty())
    res += "<bitstr>" + codeddata + "</bitstr>";

  if (!codedac.empty())
    res += "<ac>" + codedac + "</ac>";

  res += "</vomsans>";

  return res;
}

bool XML_Req_Decode(const std::string &message, request &r)
{
  struct req d;

  d.r = &r;
  d.value="";
  d.depth = d.error = 0;
  r.order = "";
  r.targets = "";
  r.lifetime = r.version = 0;
  r.base64 = false;

  XML_Parser p = XML_ParserCreate(NULL);

  XML_SetUserData(p, (void*)&d);
  XML_SetElementHandler(p,startreq,endreq);
  XML_SetCharacterDataHandler(p,handlerreq);

  int res = XML_Parse(p, message.data(), message.size(), 1);

  XML_ParserFree(p);

  return res != 0;
}

bool XML_Ans_Decode(const std::string &message, answer &a)
{
  struct ans d;
  d.a = &a;
  d.value = "";
  d.depth = d.error = 0;

  XML_Parser p = XML_ParserCreate(NULL);
  XML_SetUserData(p, (void *)&d);
  XML_SetElementHandler(p,startans,endans);
  XML_SetCharacterDataHandler(p,handlerans);
  int res = XML_Parse(p, message.data(), message.size(), 1);
  XML_ParserFree(p);

  return res != 0;
}

extern "C" {
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
    e.num     = a->num;
    e.message = a->message;
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
  else if (!strcmp(name, "warning")) {
    struct errorp e;
    e.num = WARN_OFFSET;
    e.message = a->value;
    a->a->errs.push_back(e);
  }
  else if ((!strcmp(name, "code")) && 
           (a->depth == 3)) {
    const char *msg = a->value.c_str();

    if (!strcmp(msg, "NoSuchUser"))
      a->num = ERR_NOT_MEMBER;
    else if (!strcmp(msg, "SuspendedUser"))
      a->num = ERR_SUSPENDED;
    else if (!strcmp(msg, "BadReqquest"))
      a->num = ERR_WITH_DB;
    else
      a->num = ERR_UNEXPECTED_ERROR;
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
}
