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

#include "log.h"
#include <stdio.h>
#include <string.h>
#include <dirent.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

static int filetrans(void *data, loglevels lev)
{
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
  
  return (ret != -1);
}

static int fileoutputter(void *data, int fd, int lev, const char *s)
{
  return bwrite(fd, s);
}

static void filedestroy(void *data)
{}

void *FILEStreamerAdd(void *h, FILE *f, const char *name, int maxlog, int code, int reload)
{
  if (h && f) {
    if(LogAddStreamer(h, f, (void *)f, name, maxlog, code, filetrans, fileoutputter, filedestroy, reload))
      return f;
  }
  return 0;
}

int FILEStreamerRem(void *h, void *f)
{
  if (h && f)
    return LogRemStreamer(h, f);
  return 0;
}

 
int logfile_rotate(const char * name)
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

  pos = dirname = fname = newname = oldname = NULL;

/*   // get the name of the directory and of the file */

  newname = malloc(strlen(name)+26);
  oldname = malloc(strlen(name)+26);
  fname   = malloc(strlen(name)+5);
  dirname = malloc(strlen(name)+2);

  if (!fname || !newname || !oldname || !dirname)
    goto err;

  strcpy(fname, name);
  strcat(fname, "-lck");

  if ((fd = open(fname, O_CREAT|O_EXCL|O_RDONLY)) != -1) {
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
      while ((de = readdir(dir))) {
        pos = strrchr(de->d_name, '.');
        if (pos && 
            pos - de->d_name == strlen(basename) &&
            strncmp(basename, de->d_name, strlen(basename)) == 0 &&
            atoi((++pos)) > max)
          max = atoi(pos);
      }
    }
    closedir(dir);
    

/*     // rename each file increasing the suffix */
  
    if (max) {
      for(i = max; i > 0 ; --i) {
        char s[24];
        
        strcpy(newname, name);
        strcat(newname, ".");
        sprintf(s, "%d", i+1);
        strcat(newname, s);

        strcpy(oldname, name);
        strcat(oldname, ".");
        sprintf(s, "%d", i);
        strcat(oldname, s);
    
        if (rename(oldname, newname) == -1)
          res = 0;
      }
    }
/*     // rename the main file to .1  */

    newname = (char *)malloc((strlen(name) + 3) * sizeof(char));
    if (newname) {
      strcpy(newname, name);
      strcat(newname, ".1");
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
