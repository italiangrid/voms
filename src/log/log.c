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

#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdlib.h>
#include <time.h>
#include <stdio.h>
#include <limits.h>
#include <string.h>
#include <syslog.h>
#include <stdarg.h>
#include <ctype.h>
#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <signal.h>

#include "log.h"
#include "streamers.h"

static char *typenames[] = { "STARTUP", "REQUEST", "RESULT" };

static char *levnames[] = { "LOG_ERROR", "LOG_WARN", "LOG_INFO", "LOG_DEBUG", "NONE"};

struct OutputStream {
  void   *userdata;
  char   *name;
  void * (*initter)();
  int    (*outputter)(void *, const char *);
  void   (*destroyer)(void *);
  void   (*optioner)(void *, const char *, const char *);
  int     active;

  struct OutputStream *next;
};

struct LogInfo {
  loglevels   currlev;
  int         currtype;
  logtypes    deftype;
  const char *format;
  const char *dateformat;
  const char *service;
  int         fd;
  struct OutputStream *streamers;
};

void *LogInit()
{
  struct LogInfo *info = NULL;

  info = calloc(1, sizeof(struct LogInfo));
  info->fd = -1;
  if (info) {
    FILEStreamerAdd(info);
    SYSLOGStreamerAdd(info);
  }

  return info;
}

void LogOption(void *data, const char *name, const char *value)
{
  struct LogInfo *li=(struct LogInfo *)data;

  struct OutputStream *stream = li->streamers;

  while (stream) {
    stream->optioner(stream->userdata, name, value);
    stream = stream->next;
  }
}

void LogOptionInt(void *data, const char *name, int value)
{
#define INTSIZE (((sizeof(int)*CHAR_BIT)/3)+2)
  static char val[INTSIZE];

  memset(val, 0, INTSIZE);
#undef INTSIZE
  sprintf(val, "%d", value);

  LogOption(data, name, val);
}

void LogActivate(void *data, const char *name)
{
  struct LogInfo *li=(struct LogInfo *)data;
  struct OutputStream *stream;

  if (!li)
    return;

  stream = li->streamers;

  while (stream) {
    if (strcmp(name, stream->name) == 0) {
      stream->userdata = stream->initter();
      if (stream->userdata)
        stream->active = 1;
    }
    stream = stream->next;
  }
}

void LogDeactivate(void *data, const char *name)
{
  struct LogInfo *li=(struct LogInfo *)data;
  struct OutputStream *stream;

  if (!li)
    return;

  stream = li->streamers;

  while (stream) {
    if (strcmp(name, stream->name) == 0) {
      stream->destroyer(stream->userdata);
      stream->userdata = NULL;
      stream->active = 0;
    }
    stream = stream->next;
  }
}

void *LogAddStreamer(void *data, const char *name,
                     void * (*i)(),
                     int (*o)(void *, const char *s), 
                     void (*d)(void *),
                     void (*op)(void *, const char *, const char *))
{
  struct LogInfo *li=(struct LogInfo *)data;
  struct OutputStream *out = NULL;

  out = malloc(sizeof(struct OutputStream));
  if (out) {
    out->userdata   = NULL;
    out->name       = (char *)name;
    out->initter    = i;
    out->outputter  = o;
    out->destroyer  = d;
    out->optioner   = op;
    out->active     = 0;
    out->next       = li->streamers;
    li->streamers = out;

  }
  return out;
}

void LogDestroy(void *data)
{
  free(data);
}

loglevels LogLevel(void *data, loglevels l)
{
  struct LogInfo *li=(struct LogInfo *)data;
  loglevels oldl = LEV_INFO;

  if (li) {
    oldl = li->currlev;
    li->currlev = l;
  }
  return oldl;
}

logtypes LogType(void *data, int t)
{
  struct LogInfo *li=(struct LogInfo *)data;
  logtypes oldt = T_STARTUP;

  if (li) {
    oldt = li->currtype;
    li->currtype = t;
  }
  return oldt;
}

logtypes SetCurLogType(void *data, logtypes t)
{
  struct LogInfo *li=(struct LogInfo *)data;
  logtypes oldt = T_STARTUP;

  if (li) {
    oldt = li->deftype;
    li->deftype = t;
  }
  return oldt;
}

const char *LogDateFormat(void *data, const char *format)
{
  struct LogInfo *li = (struct LogInfo *)data;
  const char *oldfmt = NULL;

  if (li) {
    oldfmt = li->dateformat;
    li->dateformat = strdup(format);
    if (!li->dateformat) {
      li->dateformat = oldfmt;
      return NULL;
    }
  }
  return oldfmt;
}

const char *LogService(void *data, const char *servicename)
{
  struct LogInfo *li = (struct LogInfo *)data;
  const char *oldname = NULL;

  if (li) {
    oldname = li->service;
    li->service = strdup(servicename);
    if (!li->service) {
      li->service = oldname;
      return NULL;
    }
  }
  return oldname;
}

const char *LogFormat(void *data, const char *format)
{
  struct LogInfo *li=(struct LogInfo *)data;
  const char *oldfmt = NULL;

  if (li) {
    oldfmt = li->format;
    li->format = strdup(format);
    if (!li->format) {
      li->format = oldfmt;
      return NULL;
    }
  }
  return oldfmt;
}

static int LogOutput(void *data, const char *str)
{
  struct LogInfo *li=(struct LogInfo *)data;

  struct OutputStream *stream = li->streamers;

  while (stream) {
    if (stream->active)
      stream->outputter(stream->userdata, str);
    stream = stream->next;
  }
  return 1;
}

static char *StringAdd(char *dest, const char *src, signed int len)
{
  char *tmp = NULL;
  int slen;

  if (!src)
    return dest;

  slen = strlen(src);

  if ((tmp = malloc((dest ? strlen(dest) : 0) + (((len == -1) || (slen < len)) ? slen : len)  + 1))) {
    tmp[0]='\0';
    if (dest)
      tmp = strcpy(tmp, dest);
    if (len == -1)
      tmp = strcat(tmp, src);
    else
      tmp = strncat(tmp, src, len);
  }

  free(dest);
  return tmp;
}

int LogMessageF(const char *func, int line, const char *file, void *data, loglevels lev, logtypes type, const char *format, ...)
{
  va_list v;
  char *str = NULL;
  int len = 0;
  int plen;
  int res = 0;
  struct LogInfo *li=(struct LogInfo *)data;


  if (!data)
    return 1;

  /* Ensures that LOG_NONE level means nothing is logged. */
  if (lev >= LEV_NONE) lev = LEV_DEBUG;

  if (li) {
    if ((li->currlev >= lev) || (li->currlev == LEV_DEBUG)) {
      do {
        len += 50;
        str = realloc(str, len);

        if (str) {
          va_start(v, format);
          plen = vsnprintf(str, len, format, v);
          va_end(v);
        }
      } while (str && (plen>=len));
      
      if (str) {
        res = LogMessage(data, lev, type, str, func, line, file);
        free(str);
      }
      return res;
    }
  }
  return 1;
}

static signed int GetLen(const char **message)
{
  signed int i = 0;  
  const char *tmp;

  if (!message || !(*message))
    return -1;

  tmp = *message;

  if (!isdigit(*tmp))
    return -1;

  while (isdigit(*tmp)) {
    i *= 10;
    i += (*tmp) - '0';
    tmp++;
  }

  *message = tmp;

  return i;
}

int LogMessage(void *data, loglevels lev, logtypes type, const char *message, const char *func, int line, const char *file)
{
  struct LogInfo *li=(struct LogInfo *)data;
  signed int len = 0;
  char *msgcopy = NULL;

  if (!data)
    return 1;

  /* Ensures that LOG_NONE level means nothing is logged. */
  if (lev >= LEV_NONE) lev = LEV_DEBUG;

  if (li) {
    if (type == T_PRE) 
      type = li->deftype;

    LogOption(data, "LEVEL", levnames[lev]);

    if (((li->currlev >= lev) && (li->currtype & type)) || 
        (li->currlev == LEV_DEBUG)) {
      const char *format = li->format;
      int mode = 0;
      char *str = NULL;
      char *holder = NULL;

      msgcopy = strdup(message);
      holder = msgcopy;

      if (!msgcopy)
        return 0;

      while (*holder != '\0') {
        if (!isprint(*holder))
          *holder = '.';
        ++holder;
      }

      while (*format) {
        switch(*format) {

        case '%':
          if (mode == 1) {
            str = StringAdd(str, "%", len);
            mode=0;
          }
          else if (mode == 0) {
            len = GetLen(&format);
            mode = 1;
          }
          else 
            goto err;
          break;

        case 'm':
          if (mode == 0)
            str = StringAdd(str, "m", len);
          else if (mode == 1) {
            str = StringAdd(str, msgcopy, len);
            mode = 0;
          }
          else 
            goto err;
          break;

        case 'd':
          str = StringAdd(str, "%d", len);
          break;

        case 'p':
          if (mode == 0)
            str = StringAdd(str, "p", len);
          else if (mode == 1) {
            pid_t pid = getpid();
            char val[(((sizeof(pid_t)*CHAR_BIT)/3)+2)];
            
            sprintf(val,"%d",(int)pid);
            str = StringAdd(str, val, len);
            mode = 0;
          }
          else 
            goto err;
          break;

        case 's':
          if (mode == 0)
            str = StringAdd(str, "s", len);
          else if (mode == 1) {
            if (li->service)
              str = StringAdd(str, li->service, len);
          }
          else 
            goto err;
          break;

        case 'f':
          if (mode == 0)
            str = StringAdd(str, "f", len);
          else if (mode == 1) {
            str = StringAdd(str, file, len);
          }
          else 
            goto err;
          break;

        case 'l':
          if (mode == 0)
            str = StringAdd(str, "l", len);
          else if (mode == 1) {
            char val[(((sizeof(pid_t)*CHAR_BIT)/3)+2)];
            
            sprintf(val,"%d",line);

            str = StringAdd(str, val, len);
          }
          else 
            goto err;
          break;

        case 'T':
          if (mode == 0)
            str = StringAdd(str, "N", len);
          else if (mode == 1) {
            int i = 0;
            int k = 0x01;
            while (!(type&k))
              k <<= 1, i++;
            str = StringAdd(str, typenames[i], len);
          }
          else 
            goto err;
          break;

        case 't':
          if (mode == 0)
            str = StringAdd(str, "n", len);
          else if (mode == 1) {
            char val[(((sizeof(pid_t)*CHAR_BIT)/3)+2)];

            sprintf(val,"%d",type);

            str = StringAdd(str, val, len);
          }
          else 
            goto err;
          break;

        case 'v':
          if (mode == 0)
            str = StringAdd(str, "v", len);
          else if (mode == 1) {
            char val[(((sizeof(pid_t)*CHAR_BIT)/3)+2)];

            sprintf(val,"%d",lev);

            str = StringAdd(str, val, len);
          }
          else 
            goto err;
          break;

        case 'V':
          if (mode == 0)
            str = StringAdd(str, "V", len);
          else if (mode == 1) {
            str = StringAdd(str, levnames[lev], len);
          }
          else 
            goto err;
          break;

        case 'F':
          if (mode == 0)
            str = StringAdd(str, "F", len);
          else if (mode == 1) {
            if (func)
              str = StringAdd(str, func, len);
          }
          else 
            goto err;
          break;

        case 'h':
          if (mode == 0)
            str = StringAdd(str, "h", len);
          else if (mode == 1) {
            struct utsname u;
            if (!uname(&u))
              str = StringAdd(str, u.nodename, len);
            else 
              goto err;
          }
          else 
            goto err;
          break;
        default:
          {
            char s[2];
            s[0] = *format;
            s[1] = '\0';
            str = StringAdd(str, s, -1);
          }
          mode =0;
          break;
        }
        format++;
      }
      str = StringAdd(str, "\n", -1);
      LogOutput(data, str);
      free(str);
    }
  }
  free(msgcopy);
  return 1;
 err:
  free(msgcopy);
  return 0;
}
