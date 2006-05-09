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

static char *typenames[] = { "STARTUP", "REQUEST", "RESULT" };

static char *levnames[] = { "ERROR", "WARN", "INFO", "DEBUG", "NONE"};

static pid_t loggerprocess = 0;
static pid_t ownerprocess = 0;

void SetOwner(pid_t pid)
{
  ownerprocess = pid;
}

extern int logfile_rotate(const char *);


void killogger(void)
{
  int status;

  if (loggerprocess && (ownerprocess == getpid())) {
    kill(loggerprocess, SIGKILL);
    waitpid(loggerprocess, &status, 0);
  }
}

struct OutputStream {
  void *id;
  void *userdata;
  int in;
  int out;
  char *fifoname;
  int (*translater)(void *, loglevels);
  int (*outputter)(void *, int, int, const char *);
  void (*destroyer)(void *);

  struct OutputStream *next;
};

struct LogInfo {
  loglevels   currlev;
  int         currtype;
  logtypes    deftype;
  const char *format;
  const char *dateformat;
  const char *service;
  struct OutputStream *streamers;
};

void *LogInit()
{
  return calloc(1, sizeof(struct LogInfo));
}

int LogBuffer(FILE *f, void *logh, loglevels lev, logtypes type, const char *format)
{
  int id;
  struct stat st;
  char *mem;

  if (!f || !logh || !format) return 1;

  id = fileno(f);

  if (fstat(id, &st)) {
    if ((mem = (char *)mmap(0, st.st_size, PROT_READ, 0, id, 0))) {
      LOGM(VARP, logh, type, lev, format, mem);
      munmap(mem, st.st_size);
      return 1;
    }
  }
  return 0;
}

int LogRemStreamer(void *data, void *id)
{
  struct LogInfo *li=(struct LogInfo *)data;
  struct OutputStream *cur = NULL, *tmp = NULL;

  if (li) {
    cur = tmp = li->streamers;
      while (cur && cur->id != id) {
        tmp = cur;
        cur = cur->next;
      }
    if (cur) {
      if (cur == li->streamers)
        li->streamers = cur->next;
      else
        tmp->next = cur->next;
      cur->destroyer(cur->userdata);
      free(cur);
      return 1;
    }
  }
  return 0;
}

static int bread(int fd, char** buffer)
{
  int reload = 0;
  int offset = 0;
  int slen = 0;

  if(read(fd, &slen, sizeof(int)) < sizeof(int))
    return 0;

  if (slen == -1) {
    reload = 1;
    if(read(fd, &slen, sizeof(int)) < sizeof(int))
      return 0;
  }

  *buffer = malloc(slen * sizeof(char) + 1);
  
  if (*buffer) {
    while (offset < slen)
      offset += read(fd, *buffer + offset, (slen - offset > PIPE_BUF ? PIPE_BUF : slen - offset));
    (*buffer)[offset] = '\0';
  }
  return (reload ? -1 : offset);
}

void StartLogger(void * data, const char *name, int maxlog)
{
  struct LogInfo * li = (struct LogInfo *)data;
  struct OutputStream * out = li->streamers;

  pid_t pid = fork();

  if (pid) {
    loggerprocess = pid;
    ownerprocess = getpid();
    atexit(killogger);
  }

  if (!pid) {
    long flen;
    FILE * f;
    char * buffer;
    int ret;
    int counter = 1;

/*     #ifndef HAVE_MKFIFO */
/*         close(out->out); */
/*     #endif */

/* //#ifndef HAVE_MKFIFO  */
/*     close(out->out); */
/*     //#endif */

#ifdef HAVE_MKFIFO
    out->in = open(out->fifoname, O_RDONLY);
#endif

    for(;;) {
      counter--;

      flen = ftell((FILE *)out->userdata);
      if (flen > maxlog) {

        if (!logfile_rotate(name)) {
          fwrite("VOMS: LOGGING ROTATION ERROR\n", sizeof(char), 29, (FILE *)(out->userdata));
        }

        f = fopen(name, "a+");
        if(f) {
          fclose(out->userdata);
          /*          out->userdata = out->id = 0;*/
          setbuf(f, NULL);
          out->userdata = f;
          out->id = f; 
        }
      }
      

      ret = bread(out->in, &buffer);
      if (ret > 0) {
        if (out->userdata)
          fwrite(buffer, sizeof(char), strlen(buffer), (FILE *)(out->userdata));
        free(buffer);
      }
      else if (ret == -1) {
        char *newname;

        newname = malloc(strlen(buffer) + 1);
        strcpy(newname, buffer);
        free(buffer);

        f = fopen(newname, "a+");
        if(f) {
          fclose(out->userdata);          
/*         out->userdata = out->id = 0; */
          setbuf(f, NULL);
          out->userdata = f;
          out->id = f; 
        } 
      }
    }
  }
  /*close(out->in);*/
}


void *LogAddStreamer(void *data, void *id, void *userdata, const char *name, int maxlog, int code,
                     int (*t)(void *, loglevels), 
                     int (*o)(void *, int, int, const char *s), void (*d)(void *), int reload)
{
  struct LogInfo *li=(struct LogInfo *)data;
  struct OutputStream *out = NULL;

  int fd[2];
  char * fifo;

  if (!reload)
    out = NULL;
  else 
    out = li->streamers;

  /* when reloading options, simply notify the new log file to the child process */
  if (reload) {
    int len = -1;
    write(out->in, &len, sizeof(int));
    len = strlen(name);
    write(out->in, &len, sizeof(int));
    write(out->in, name, len);
    return out;
  }
  
#ifdef HAVE_MKFIFO
  fifo = malloc(30);
  strcpy(fifo, "/tmp/voms_log_fifo_");
  sprintf(fifo + 19, "%i", code);
  
  if(mkfifo(fifo, S_IRUSR | S_IWUSR))
  {
    if(errno != EEXIST)
    {
      printf("Unable to make fifo : %s\n", strerror(errno));
      exit(1);
    }
  }

  if (li && userdata && t && o && d) {
    out = malloc(sizeof(struct OutputStream));
    if (out) {
      out->fifoname=fifo;
      out->id = id;
      out->userdata = userdata;
      out->in = fd[0];
      out->out = fd[1];
      out->translater = t;
      out->outputter = o;
      out->destroyer = d;
      out->next = li->streamers;
      li->streamers = out;
    }
  }

  StartLogger(data, name, maxlog);
  
  fd[0] = open(fifo, O_WRONLY, O_NONBLOCK);
  out->in = out->out = fd[0];
  if (fd[0] == -1) {
    printf("Unable to open fifo : %s\n", strerror(errno));
    exit(1);
  }

  fd[1] = fd[0];

/*   //  free(fifo); */
#else
  if (pipe(fd))
  {
    printf("Unable to open pipe : %s\n", strerror(errno));
    exit(1);
  }

  if (li && userdata && t && o && d) {
    out = malloc(sizeof(struct OutputStream));
    if (out) {
      out->fifoname=fifo;
      out->id = id;
      out->userdata = userdata;
      out->in = fd[0];
      out->out = fd[1];
      out->translater = t;
      out->outputter = o;
      out->destroyer = d;
      out->next = li->streamers;
      li->streamers = out;
    }
  }
#endif

#ifndef HAVE_MKFIFO
  StartLogger(data, name, maxlog);
#endif

#ifndef HAVE_MKFIFO
  /* close reading end of the pipe */
  close(out->in);
#endif

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
  if (data) {
    struct OutputStream *out = li->streamers;

    while(out) {
      out->outputter(out->userdata, out->out, out->translater(out->userdata, lev), str);
      out = out->next;
    }
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
  signed int len;
  char *msgcopy = NULL;

  if (!data)
    return 1;

  /* Ensures that LOG_NONE level means nothing is logged. */
  if (lev >= LEV_NONE) lev = LEV_DEBUG;

  if (li) {
    if (type == T_PRE) 
      type = li->deftype;
    if (((li->currlev >= lev) && (li->currtype & type)) || 
        (li->currlev == LEV_DEBUG)) {
      const char *format = li->format;
      int mode = 0;
      const char *dateformat = (li->dateformat ? li->dateformat : "%c");
      char *str = NULL;

      msgcopy = strdup(message);
      char *holder = msgcopy;

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
          if (mode == 0)
            str = StringAdd(str, "d", len);
          else if (mode == 1) {
            if (dateformat) {
              char *data = NULL;
              int datasize=256;
              size_t len = 0;
              time_t t;
              struct tm *ti;
              
              time(&t);
              ti = localtime(&t);

              do {
                free(data);
                if ((data = malloc(datasize)))
                  len = strftime(data, datasize, dateformat, ti);
                datasize += 50;
              } while (len == 0 && data);
              if (data)
                str = StringAdd(str, data, len);
              free(data);
            }
            mode = 0;
          }
          else 
            goto err;
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
