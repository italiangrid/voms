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

extern "C" {
#include <stdio.h>
#include <errno.h>
#include <termios.h>
#include <pwd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/mman.h>
#include <unistd.h>
#include <stdlib.h>
}

#include <string>

extern "C" {
#include "log.h"
}

#define MAXSIZE 1024
static char password[MAXSIZE]; /* Will contain the password */

static struct rlimit newlimit = {0,0};
static pid_t fatherpid=0;      /* Will contain the pid of the process that
				* obtained the password.*/

/*
 * Function:
 *   freepasswd()
 *
 * Description:
 *   This function deletes the password and unlocks the memory that contained
 *   it.
 *
 * Parameters:
 *   NONE.
 *
 * Result:
 *   NONE.
 */
static void 
freepasswd(void)
{
  int i;

  for (i = 0; i < MAXSIZE; i++)
    password[i]='\0';

  munlock(password, MAXSIZE);
}

/*
 * Function:
 *   fun()
 *
 * Description:
 *   This function is called during the process shutdown to delete the password
 *   from memory. A check is made to ensure that the process that is closing is
 *   the same one the got the password in memory.
 *
 * Parameters:
 *   NONE.
 *
 * Result:
 *   NONE.
 */
static void 
fun(void) 
{
  if (getpid() == fatherpid) {
    freepasswd();
  }
}

/*
 * Function:
 *   getpasswd(passfile)
 *
 * Description:
 *   This file reads a password into memory, from a file if 'passfile' is not
 *   NULL or from the console. It MUST be called only one time.
 *
 * Parameters:
 *   'passfile' - The name of the file that contains the password or NULL.
 *
 * Result:
 *   Failure:
 *     0.
 *   Success:
 *     1
 */
bool
getpasswd(std::string passfile, void *logh)
{
  FILE *f = NULL;
  int ch = 0;
  int i = 0;
  struct termios term, term2;
  struct stat pf_stat;
  uid_t uid;

  LOGM(VARP, logh, LEV_INFO, T_STARTUP, "Password file: %s", passfile.c_str());

  /* register the pid */
  fatherpid = getpid();
  atexit(fun);

  uid = geteuid();

  /* no core dumps */
  if (setrlimit(RLIMIT_CORE, &newlimit) != 0)
    return false;

  if (uid == 0) {
    /* Need to be root to lock memory */
    /* lock needed memory */
    if (mlock(password, MAXSIZE) != 0)
      return false;

    if (mlock(&ch, sizeof(ch)) != 0) {
      munlock(password, MAXSIZE);
      return false;
    }
  }
  if (passfile.empty()) {
    /* read from the console */
    if ((f = fopen("/dev/tty","r+"))) {
      fprintf(f, "password: ");
      fflush(f);
      if (0 == tcgetattr(fileno(f), &term)) {
        term2 = term;
        term.c_lflag &= ~(ECHO|ISIG);
        if ((tcsetattr (fileno (f), TCSAFLUSH, &term)))
          goto error;
      }
      else
        goto error;

      while (((ch = fgetc(f)) != '\n') && (ch != EOF) && (i < (MAXSIZE-1)))
        password[i++] = ch;

      if (i >= (MAXSIZE - 1)) {
        LOG(logh, LEV_ERROR, T_STARTUP, "password too long!");
        goto error;
      }

      if (ch == EOF) {
        LOG(logh, LEV_ERROR, T_STARTUP, "missing new line at end of file!");
        goto error;
      }

      password[i] = '\0';
      tcsetattr(fileno(f),TCSAFLUSH, &term2);
      fflush(f);
      fprintf(f,"\n");
    }
    else
      goto error;
  }
  else {
    /* read from a file */

    if ((f = fopen(passfile.c_str(),"r"))) {
      if (fstat(fileno(f),&pf_stat) == 0) {
        if (pf_stat.st_mode != (S_IRUSR|S_IRGRP|S_IWUSR|S_IFREG)) {
          LOG(logh, LEV_ERROR, T_STARTUP, "Wrong permissions of password file!\n"
              "Needs to be 640.\n");
          goto error;
        }
        if(pf_stat.st_uid != 0 && pf_stat.st_uid != uid) {
          LOG(logh, LEV_ERROR, T_STARTUP, "Wrong ownership of password file %s\n"
              "Needs to be owned by root or by the user.\n");
          goto error;
        }
        if (!setvbuf(f, NULL, _IONBF, 0)) {
          while (((ch = fgetc(f)) != '\n') && (ch != EOF) && (i < (MAXSIZE-1)))
            password[i++] = ch;
          
          if (i >= (MAXSIZE - 1)) {
            LOGM(VARP, logh, LEV_ERROR, T_STARTUP, "Password too long! Max length = %d", (MAXSIZE-1));
            goto error;
          }

          if (ch == EOF) {
            LOG(logh, LEV_ERROR, T_STARTUP, "Missing new line at end of file!");
            goto error;
          }

          password[i] = '\0';
        }
        else goto error;
      }
      else goto error;
    }
    else goto error;
  }
  
  fclose(f);
  ch = 0;

  if (uid == 0)
    munlock(&ch, sizeof(ch));

  return true;

 error:
  ch = 0;
  for (i = 0; i < MAXSIZE; i++)
    password[i] = '\0';

  if (uid == 0) {
    munlock(&ch, sizeof(ch));
    munlock(password, MAXSIZE);
  }

  if (f)
    fclose(f);
  return false;
}

/*
 * Function:
 *   passwd()
 *
 * Description:
 *   This function returns the password entered via the getpasswd() function.
 *
 * Parameters:
 *   NONE.
 *
 * Result:
 *   The password. This value is meaningless if getpasswd() hasn't been called
 *   before this function.
 */
char *
passwd(void)
{
  return password;
}
