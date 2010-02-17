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

struct localdata {
  char *name;
  char *dateformat;
  int maxlog;
  int fd;
  int level;
};

static int filereopen(struct localdata *ld);
static int logfile_rotate(const char * name);

static char *translate(char *format, char *date)
{
  char *position = strstr(format, "%d");
  char *newstring = NULL;

  while (position) {
    newstring = malloc(strlen(format) + strlen(date) + 1 - 2);
    *position++='\0';
    position++;
    newstring = strcpy(newstring, format);
    newstring = strcat(newstring, date);
    newstring = strcat(newstring, position);
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
    ld->level    = -1;
  }

  return ld;
}

static void fileoptioner(void *data, const char *name, const char *value)
{
  struct localdata *ld = (struct localdata *)data;

  if (!ld)
    return;

  if (strcmp(name, "LEVEL") == 0)
    ld->level=atoi(value);
  else if (strcmp(name, "NAME") == 0) {
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
  int i = 0;
  char *pos, *dirname, *newname, *oldname, *basename;
  int max = 0;
  DIR * dir = NULL;
  struct dirent * de = NULL;
  int result = 0;
  char *fname = NULL;
  int res = 1;
  int fd;
  int namelen = strlen(name);

  pos = dirname = fname = newname = oldname = NULL;

  /* get the name of the directory and of the file */

  newname = malloc(namelen+26);
  oldname = malloc(namelen+26);
  fname   = malloc(namelen+5);
  dirname = malloc(namelen+2);

  if (!fname || !newname || !oldname || !dirname)
    goto err;

  strcpy(fname, name);
  strcat(fname, "-lck");

  if ((fd = open(fname, O_CREAT|O_EXCL|O_RDONLY, S_IRUSR|S_IWUSR)) != -1) {
    pos = strrchr(name, '/');
  
    if (pos == NULL) {
      dirname[0] = '.';
      dirname[1] = '\0';
      basename = pos;
    }
    else if (pos == name) {
      dirname[0]='/';
      dirname[1]='\0';
      basename = ++pos;
    }
    else {
      strncpy(dirname, name, pos - name);
      dirname[pos-name] = '\0';
      basename = ++pos;
    }

    dir = opendir(dirname);
    if (dir) {
      baselen = strlen(basename);

      while ((de = readdir(dir))) {
        pos = strrchr(de->d_name, '.');
        if (pos && atoi(pos+1) > max &&
            (size_t)(pos - de->d_name) == baselen &&
            strncmp(basename, de->d_name, baselen) == 0)
          max = atoi(pos+1);
      }
    }
    closedir(dir);
    

    /* rename each file increasing the suffix */
    strcpy(newname, name);
    newname[namelen]='.';

    strcpy(oldname, name);
    oldname[namelen]='.';
  
    if (max) {
      for(i = max; i > 0 ; --i) {
        char s[24];
        
        sprintf(s, "%d", i+1);
        strcpy(newname + namelen +1, s);

        sprintf(s, "%d", i);
        strcpy(oldname + namelen +1, s);
    
        (void)rename(oldname, newname);
      }
    }

    /* rename the main file to .1  */
    if (newname) {
      newname[namelen+1]='1';
      newname[namelen+2]='\0';
      if (rename(name, newname) == -1)
        res = 0;
      result = 1;
    }
    
    unlink(fname);
    close(fd);
  }

 err:
  free(dirname);
  free(fname);
  free(newname);
  free(oldname);

  if (result && res)
    return 1;
  else
    return 0;
}
