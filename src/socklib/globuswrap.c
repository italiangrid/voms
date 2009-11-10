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
#include "replace.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/mman.h>

#include <stdlib.h>
#include <stdio.h>

#include <globus_gss_assist.h>

#include "log.h"

int my_send(OM_uint32 *m, const gss_ctx_id_t h, char *data, size_t len,
	    int *tok_stat, int (*gt)(void *, void *, size_t), 
	    void *get_ctx, void *logh)
{
  int id;
  FILE *f;
  OM_uint32 res;
  char fname[]="/tmp/XXXXXX";
  int trueres= 0;
  int done = 0;

  id = mkstemp(fname);
  if (id) {
    f = fdopen(id, "w");
    if (f) {
      res = globus_gss_assist_wrap_send(m, h, data, len, tok_stat, gt, get_ctx, f);
      fflush(f);
      if (GSS_ERROR(res)) {
        char *str = NULL;
        globus_gss_assist_display_status_str(&str,
                                             "Failed to send data:",
                                             res, *m, *tok_stat);
        done = LogBuffer(f, logh, LEV_ERROR, -1, str);
        LOG(logh, LEV_ERROR, -1, str);
        free(str);
      }
      else
        trueres=1;
      fclose(f);
      id = -1;
    }
    if (id != -1)
      close(id);
    unlink(fname);
  }
  if (!trueres && !done)
    LOG(logh, LEV_ERROR, -1, "Globus error: unable to log");
  return trueres;
}

int my_recv(OM_uint32 *m, const gss_ctx_id_t h, char **data, size_t *len, int *t_s,
	    int (*gt)(void *, void **, size_t *), void *gs, void *logh)
{
  int id;
  FILE *f;
  OM_uint32 res;
  char fname[]="/tmp/XXXXXX";
  int trueres= 0;
  int done = 0;

  id = mkstemp(fname);
  if (id) {
    f = fdopen(id, "w");
    if (f) {
      res = globus_gss_assist_get_unwrap(m, h, data, len, t_s, gt, gs, f);
      fflush(f);
      if (GSS_ERROR(res)) {
        char *str = NULL;
        globus_gss_assist_display_status_str(&str,
                                             "Failed to receive data: ",
                                             res, *m, *t_s);
        done = LogBuffer(f, logh, LEV_ERROR, -1, str);
        LOG(logh, LEV_ERROR, -1, str);
        free(str);
      }
      else if (*len == 0) {
        LOG(logh, LEV_DEBUG, -1, "Received empty fragment. Retry");
        return my_recv(m, h, data, len, t_s, gt, gs, logh);
      }
      else 
        trueres=1;


      fclose(f);
      id = -1;
    }
    if (id != -1)
      close(id);
    unlink(fname);
  }
  if (!trueres && !done)
    LOG(logh, LEV_ERROR, -1, "Globus error: unable to log");

  LOGM(VARP, logh, LEV_ERROR, -1, "trueres = %d\n", trueres);
  return trueres;
}
