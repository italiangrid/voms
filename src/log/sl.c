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

#include <stdlib.h>
#include <string.h>
#include <syslog.h>

struct localdata {
  int feature;
  int level;
  char *service;
};

const char *level[] = {"LOG_ERROR", "LOG_WARN", "LOG_INFO", "LOG_DEBUG",
                       NULL };
const int   levelvalue[] = { LOG_ERR,
                             LOG_WARNING, LOG_NOTICE, LOG_DEBUG, 0};

static int syslogtrans(const char *v)
{
  int i = -1;
  int result = LOG_ALERT;

  while (level[++i]) {
    if (strcmp(level[i], v) == 0) {
      result = levelvalue[i];
      break;
    }
  }

  return result;
}

static char *translate(char *format)
{
  char *position = strstr(format, "%d");
  char *newstring = NULL;

  while (position) {
    newstring = malloc(strlen(format) + 1 - 2);
    *position++='\0';
    position++;
    newstring = strcpy(newstring, format);
    newstring = strcat(newstring, position);
    free(format);
    format = newstring;
    position = strstr(format, "%d");
  }

  return format;
}

static int syslogoutputter(void *data, const char *str)
{
  struct localdata *ld = (struct localdata *)data;

  if (!ld)
    return 0;

  char *realstr = strdup(str);

  realstr = translate(realstr);

  if (strlen(realstr) > 1000)
    realstr[1000]='\0';

  syslog(ld->feature|ld->level, "%s", realstr);

  free(realstr);

  return 1;
}

static void syslogoptioner(void *data, const char *name, const char *value)
{
  struct localdata *ld = (struct localdata *)data;

  if (!ld)
    return;

  if (strcmp(name, "SERVICE") == 0) {
    if (ld->service) {
      free(ld->service);
      closelog();
    }

    ld->service=strdup(value);

    openlog(ld->service, 0, LOG_DAEMON|LOG_DEBUG);
  }
  else if (strcmp(name, "FACILITY") == 0) {
    if (strcmp(value, "LOG_AUTH") == 0 ||
        strcmp(value, "LOG_AUTHPRIV") == 0)
      ld->feature = LOG_AUTHPRIV;
    else if (strcmp(value, "LOG_DAEMON") == 0)
      ld->feature = LOG_DAEMON;
    else
      ld->feature = LOG_USER;
  }
  else if (strcmp(name, "LEVEL") == 0) {
    ld->level = syslogtrans(value);
  }
}

static void *sysloginit()
{
  struct localdata *ld = malloc(sizeof(struct localdata));

  if (ld) {
    ld->feature   = LOG_DAEMON;
    ld->service   = strdup("vomsd");
    ld->level     = 0;
    openlog(ld->service, 0, LOG_DAEMON|LOG_DEBUG);
  }

  return ld;
}

static void syslogdestroyer(void *data)
{
  struct localdata *ld = (struct localdata *)data;

  free(ld->service);
  free(ld);

  closelog();

}

void *SYSLOGStreamerAdd(void *h)
{
  if (h) {
    return LogAddStreamer(h, "SYSLOG", sysloginit, syslogoutputter, 
                          syslogdestroyer, syslogoptioner);
  }
  return NULL;
}
