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

#include "log.h"
#include "streamers.h"

#include <stdio.h>
#include <string.h>
#include <dirent.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>

#include "doio.h"

struct localdata {
  char *name;
  char *dateformat;
  int maxlog;
  int fd;
};

static int filereopen(struct localdata *ld);
static int logfile_rotate(const char * name);

static char *translate(char *format, char *date)
{
  char *position = strstr(format, "%d");
  char *newstring = NULL;

  while (position) {
    *position++='\0';
    position++;
    newstring = snprintf_wrap("%s%s%s", format, date, position);
    free(format);
    format = newstring;
    position = strstr(format, "%d");
  }

  return format;
}

static int fileoutputter(void *data, const char *s)
{
  int written = 0;
  int size;
  int total = 0;
  char *output = NULL;

  struct localdata *ld = (struct localdata *)data;

  if (!ld || ld->fd == -1)
    return 0;

  off_t position = lseek(ld->fd, 0, SEEK_CUR);

  if (ld->maxlog) {
    if (position > ld->maxlog) {
      if (!logfile_rotate(ld->name) || !filereopen(ld)) {
        UNUSED(int ret);
        ret= write(ld->fd, "VOMS: LOGGING ROTATION ERROR\n", 29);
      }
    }
  }
  output = strdup(s);

  if (ld->dateformat) {
    char  *data = NULL;
    int    datasize = 256;
    size_t len = 0;

    time_t t;
    struct tm *ti;

    time(&t);
    ti = localtime(&t);

    do {
      free(data);

      if ((data = malloc(datasize)))
        len = strftime(data, datasize, ld->dateformat, ti);

      datasize += 50;
    } while (len == 0 && data);

    output = translate(output, data);
    free(data);
  }

  size = strlen(output);

  do {
    written = write(ld->fd, output + total, size - total);
    total += written;
  } while (total != size && written != -1);

  free(output);

  return 1;
}

static int filereopen(struct localdata *ld)
{
  int newfd = open(ld->name, O_WRONLY|O_CREAT|O_APPEND, S_IRUSR|S_IWUSR);

  if (newfd != -1) {
    close(ld->fd);
    ld->fd = newfd;
    return 1;
  }

  return 0;
}

static void filedestroy(void *data)
{
  struct localdata *ld = (struct localdata *)data;

  if (!ld)
    return;
  
  if (ld->fd != -1)
    close(ld->fd);

  free (ld->name);
  free(ld);
}

static void *fileinit(void)
{
  struct localdata *ld = NULL;

  ld = malloc(sizeof(struct localdata));

  if (ld) {
    ld->name = NULL;
    ld->dateformat = NULL;
    ld->fd       = -1;
    ld->maxlog   = 0;
  }

  return ld;
}

static void fileoptioner(void *data, const char *name, const char *value)
{
  struct localdata *ld = (struct localdata *)data;

  if (!ld)
    return;

  if (strcmp(name, "NAME") == 0) {
    int fd = open(value, O_WRONLY|O_CREAT|O_APPEND, S_IRUSR|S_IWUSR);

    if (fd != -1) {
      if (ld->name) {
        free(ld->name);
        if (ld->fd != -1)
          close(ld->fd);
      }

      ld->name = strdup(value);
      ld->fd = fd;
    }
  }
  else if (strcmp(name, "MAXSIZE") == 0) {
    ld->maxlog = atoi(value);
  }
  else if (strcmp(name, "DATEFORMAT") == 0) {
    if (ld->dateformat)
      free(ld->dateformat);
    ld->dateformat = strdup(value);
  }
}

void *FILEStreamerAdd(void *h)
{
  if (h) {
    return LogAddStreamer(h, "FILE", fileinit, fileoutputter, 
                          filedestroy, fileoptioner);
  }
  return NULL;
}

 
static int logfile_rotate(const char * name)
{
  char *pos, *dirname, *newname, *oldname;
  char const* basename = NULL;
  DIR * dir = NULL;
  struct dirent * de = NULL;
  int result = 0;
  char *fname = NULL;
  int fd;

  newname = NULL;

  /* get the name of the directory and of the file */

  fname   = snprintf_wrap("%s-lck", name);

  if (!fname)
    goto err;

  if ((fd = open(fname, O_CREAT|O_EXCL|O_RDONLY, S_IRUSR|S_IWUSR)) != -1) {
    int i = 0;
    int max = 0;

    pos = strrchr(name, '/');
  
    if (pos == NULL) {
      dirname = snprintf_wrap(".");
      basename = name;
    }
    else if (pos == name) {
      dirname = snprintf_wrap("/");
      basename = ++pos;
    }
    else {
      dirname = snprintf_wrap("%s", name);
      dirname[pos-name] = '\0';
      basename = ++pos;
    }

    if (!dirname)
      goto err;

    dir = opendir(dirname);
    if (dir) {
      int baselen = strlen(basename);

      while ((de = readdir(dir))) {
        pos = strrchr(de->d_name, '.');

        if (pos && atoi(pos+1) > max &&
            (size_t)(pos - de->d_name) == baselen &&
            strncmp(basename, de->d_name, baselen) == 0)
          max = atoi(pos+1);
      }
      closedir(dir);
    }
    free(dirname);

    /* rename each file increasing the suffix */
    if (max) {
      for(i = max; i > 0 ; --i) {
        newname = snprintf_wrap("%s.%d", name, i+1);
        oldname = snprintf_wrap("%s.%d", name, i);
    
        if (newname && oldname)
          (void)rename(oldname, newname);

        free(oldname);
        free(newname);
      }
    }

    newname = snprintf_wrap("%s.1", name);

    /* rename the main file to .1  */
    if (newname) {
      if (rename(name, newname) != -1)
        result = 1;
    }

    free(newname);

    unlink(fname);
    close(fd);
  }

 err:
  free(fname);

  return result;
}
