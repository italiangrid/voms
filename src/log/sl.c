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
#include <syslog.h>


static int syslogtrans(void *data, loglevels lev)
{
  switch(lev) {
  case LEV_INFO:
    return LOG_INFO; break;
  case LEV_WARN:
    return LOG_WARNING; break;
  case LEV_ERROR:
    return LOG_ERR; break;
  case LEV_DEBUG:
    return LOG_DEBUG; break;
  default:
    return LOG_ALERT; break;
  }
}

static int syslogoutputter(void *data, int fd, int lev, const char *str)
{
  syslog(LOG_USER|lev,"%s",str);
  return 1;
}

static void syslogdestroyer(void *data)
{}

void *SYSLOGStreamerAdd(void *h, int code)
{
  void *f=malloc(1);
  if (f) {
    openlog("", 0 , LOG_USER);
    if (LogAddStreamer(h, f, f, 0, 1, code, syslogtrans, syslogoutputter, syslogdestroyer, 0))
      return f;
    closelog();
  }
  return 0;
}

int SYSLOGStreamerRem(void *h, void *f)
{
  int res = 0;

  if (h && f) {
    res = LogRemStreamer(h, f);
    closelog();
    free(f);
  }
  return 0;
}
