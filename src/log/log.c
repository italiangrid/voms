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

#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/wait.h>
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
#include <signal.h>
#include <stdio.h>

#include "log.h"

#define LOG_COMMAND       'L'
#define SET_OPTION        'O'
#define ACTIVATE_BUFFER   'A'
#define DEACTIVATE_BUFFER 'D'

static char *typenames[] = { "STARTUP", "REQUEST", "RESULT" };

static char *levnames[] = { "LOG_ERROR", "LOG_WARN", "LOG_INFO", "LOG_DEBUG", "NONE"};

static pid_t loggerprocess = 0;
static pid_t ownerprocess = 0;

static void killogger(void);

extern void *FILEStreamerAdd(void *h);
extern void *SYSLOGStreamerAdd(void *h);

void SetOwner(pid_t pid)
{
  ownerprocess = pid;
  atexit(killogger);
}

static void killogger(void)
{
  int status;

  if (loggerprocess && (ownerprocess == getpid())) {
    kill(loggerprocess, SIGKILL);
    waitpid(loggerprocess, &status, 0);
  }
}

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

static void Logger(void *data, int fd);
static void Evaluate(struct LogInfo *li, char *buffer);
static void Activate(struct LogInfo *li, char *name);
static void Deactivate(struct LogInfo *li, char *name);
static void SetOption(struct LogInfo *li, char *name, char *value);
static void LogCommand(struct LogInfo *li, char *message);

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

int LogBuffer(FILE *f, void *logh, loglevels lev, logtypes type, const char *format)
{
  int id;
  struct stat st;
  char *mem;

  if (!f || !logh || !format) return 1;

  id = fileno(f);

  if (!fstat(id, &st)) {
    if ((mem = (char *)mmap(0, st.st_size, PROT_READ, 0, id, 0))) {
      LOGM(VARP, logh, type, lev, format, mem);
      munmap(mem, st.st_size);
      return 1;
    }
  }
  return 0;
}

static int bwrite(int fd, const char * s) 
{
  int ret = -1;
  
  int slen = strlen(s);
  int blen = sizeof(int) + slen;
  
  char * buffer = malloc(blen);
  if(buffer) {
    memcpy(buffer, &slen, sizeof(int));
    memcpy(buffer + sizeof(int), s, strlen(s));
    ret = write(fd, buffer, blen);
  }
  free(buffer);

  return (ret != -1);
}

static int bread(int fd, char** buffer)
{
  int reload = 0;
  int offset = 0;
  int slen = 0;
  ssize_t readbytes = -1;

  do {
    readbytes = read(fd, &slen, sizeof(int));
  } while (readbytes < 0 && (errno == EINTR
#ifdef ERESTART
                               || errno == ERESTART
#endif
                               ));

  if (readbytes != sizeof(int))
    return 0;


  *buffer = malloc(slen * sizeof(char) + 1);

  if (*buffer) {
    while (offset < slen) {
      do {
        readbytes = read(fd, *buffer + offset, (slen - offset > PIPE_BUF ? PIPE_BUF : slen - offset));
      } while (readbytes < 0 && (errno == EINTR
#ifdef ERESTART
                                   || errno == ERESTART
#endif
                                   ));
      offset += readbytes;      
    }

    (*buffer)[offset] = '\0';
  }
  return (reload ? -1 : offset);
}

void StartLogger(void *data, int code)
{
  struct LogInfo * li = (struct LogInfo *)data;

  int in = -1, out = -1;

#ifdef HAVE_MKFIFO
  char fifo[30];

  sprintf(fifo, "/tmp/voms_log_fifo_%i", code);
  
  if(mkfifo(fifo, S_IRUSR | S_IWUSR))
  {
    if(errno != EEXIST)
    {
      printf("Unable to make fifo : %s\n", strerror(errno));
      exit(1);
    }
  }
#else
  int fd[2];

  if (pipe(fd))
  {
    printf("Unable to open pipe : %s\n", strerror(errno));
    exit(1);
  }
  in = fd[0];
  out = fd[1];
#endif

  pid_t pid = fork();

  if (pid) {
    loggerprocess = pid;
/*     ownerprocess = getpid(); */
/*     atexit(killogger); */
    if (out == -1)
      out = open(fifo, O_WRONLY);
    li->fd = out;
    if (in != -1)
      close(in);
  }
  else {
    if (out != -1)
      close(out);
    if (in == -1)
      in  = open(fifo, O_RDONLY);
    Logger(data, in);
  }
}

static void Logger(void *data, int fd) 
{
  char *buffer = NULL;
  int result;

  struct LogInfo *li = data;

  if (!li)
    return;

  while(1) {
    result = bread(fd, &buffer);

    if (result) {
      if (buffer) {
        Evaluate(li, buffer);
        free(buffer);
        buffer = NULL;
      }
    }
  }
}

static void Evaluate(struct LogInfo *li, char *buffer)
{
  char *name = NULL;
  char *pos = NULL;

  switch(*buffer) {
  case ACTIVATE_BUFFER:
    name = buffer+1;
    Activate(li, name);
    break;

  case DEACTIVATE_BUFFER:
    name = buffer+1;
    Deactivate(li, name);
    break;

  case SET_OPTION:
    name = buffer+1;
    pos = strchr(name, '=');
    if (pos) {
      *pos++ = '\0';
      SetOption(li, name, pos);
    }
    break;

  case LOG_COMMAND:
    name = buffer+1;
    LogCommand(li, name);
    break;

  default:
    LogCommand(li, "Unknown logging command: ");
    LogCommand(li, buffer);
    break;
  }
}

void LogOption(void *data, const char *name, const char *value)
{
  struct LogInfo *li=(struct LogInfo *)data;
  char *buffer = NULL;

  buffer = malloc(strlen(name)+strlen(value)+3);
  buffer[0]=SET_OPTION;
  buffer[1]='\0';

  buffer = strcat(buffer, name);
  buffer = strcat(buffer, "=");
  buffer = strcat(buffer, value);
  bwrite(li->fd, buffer);
  free(buffer);

}

void LogOptionInt(void *data, const char *name, int value)
{
#define INTSIZE (((sizeof(int)*CHAR_BIT)/3)+2)
  static char val[INTSIZE];
#undef INTSIZE
  sprintf(val, "%d\0", value);

  LogOption(data, name, val);
}

void LogActivate(void *data, const char *name)
{
  struct LogInfo *li=(struct LogInfo *)data;

  char *buffer = NULL;

  buffer = malloc(strlen(name)+2);
  buffer[0]=ACTIVATE_BUFFER;
  buffer[1]='\0';

  buffer = strcat(buffer, name);
  bwrite(li->fd, buffer);
  free(buffer);
}

void LogDeactivate(void *data, const char *name)
{
  struct LogInfo *li=(struct LogInfo *)data;

  char *buffer = NULL;

  buffer = malloc(strlen(name)+2);
  buffer[0] = DEACTIVATE_BUFFER;
  buffer[1] = '\0';

  buffer = strcat(buffer, name);
  bwrite(li->fd, buffer);
  free(buffer);
}

static void Activate(struct LogInfo *li, char *name)
{
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

static void Deactivate(struct LogInfo *li, char *name)
{
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


static void SetOption(struct LogInfo *li, char *name, char *value)
{
  struct OutputStream *stream = li->streamers;

  while (stream) {
    stream->optioner(stream->userdata, name, value);
    stream = stream->next;
  }
}

static void LogCommand(struct LogInfo *li, char *message)
{
  struct OutputStream *stream = li->streamers;

  while (stream) {
    if (stream->active)
      stream->outputter(stream->userdata, message);
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

static int LogOutput(void *data, loglevels lev, const char *str)
{

  struct LogInfo *li=(struct LogInfo *)data;

  char *buffer = NULL;

  buffer = malloc(strlen(str)+2);
  buffer[0] = LOG_COMMAND;
  buffer[1] = '\0';

  buffer = strcat(buffer, str);
  bwrite(li->fd, buffer);
  free(buffer);

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
  signed int len;
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
      LogOutput(data, lev, str);
      free(str);
    }
  }
  free(msgcopy);
  return 1;
 err:
  free(msgcopy);
  return 0;
}
