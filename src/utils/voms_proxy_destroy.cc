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
/*
 * No original header was present, but the still_valid() function was
 * adapted from original Globus code.
 */

/**********************************************************************
                             Include header files
**********************************************************************/
#include "config.h"
#include "replace.h"

#include <string>

const std::string SUBPACKAGE      = "voms-proxy-destroy";

extern "C" {
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

#ifdef USE_PKCS11
#include "scutils.h"
#endif
#include "sslutils.h"
}

#include "data.h"
#include "options.h"

#include <iostream>

bool debug = false;
bool quiet = false;

/**********************************************************************
                       Define module specific variables
**********************************************************************/

static bool delete_proxy(void);
static int destroy_proxy(char *, bool);

std::string program;

static std::string file;
static bool        progversion = false;
static bool        dryrun      = false;

int
main(int argc, char **argv)
{
    if (strrchr(argv[0],'/'))
	program = strrchr(argv[0],'/') + 1;
    else
	program = argv[0];

    static std::string LONG_USAGE =		\
      "\n" \
      "    Options\n" \
      "    -help, -usage       Displays usage\n" \
      "    -version            Displays version\n" \
      "    -debug              Enables extra debug output\n" \
      "    -file <proxyfile>   Specifies proxy file name.\n" \
      "    -dry                Only go in dryrun mode.\n" \
      "    -conf <file>        Load options from file <file>.\n" \
      "    -q, -quiet          Quiet mode, minimal output.\n" \
      "\n";

    set_usage(LONG_USAGE);

    struct option opts[] = {
      {"help",        0, NULL,                OPT_HELP},
      {"usage",       0, NULL,                OPT_HELP},
      {"version",     0, (int *)&progversion, OPT_BOOL},
      {"file",        1, (int *)&file,        OPT_STRING},
      {"debug",       0, (int *)&debug,       OPT_BOOL},
      {"q",           0, (int *)&quiet,       OPT_BOOL},
      {"quiet",       0, (int *)&quiet,       OPT_BOOL},
      {"conf",        1, NULL,                OPT_CONFIG},
      {"dryrun",      1, (int *)&dryrun,      OPT_BOOL},
      {0, 0, 0, 0}
    };

    if (!getopts(argc, argv, opts))
      exit(1);

    if (progversion) {
      std::cout << SUBPACKAGE << "\nVersion: " << VERSION << std::endl;
      std::cout << "Compiled: " << __DATE__ << " " << __TIME__ << std::endl;
      exit(0);
    }

    return delete_proxy();
}


/*
 * Function:
 *   delete_proxy()
 *
 */
static bool
delete_proxy(void)
{
  char *ccaf, *cd, *of, *cf, *kf;
  proxy_cred_desc *pcd;

#ifdef WIN32
  CRYPTO_malloc_init();
#endif

  ERR_load_prxyerr_strings(0);
  SSLeay_add_ssl_algorithms();

  if ((pcd = proxy_cred_desc_new()) == NULL)
    return 0;

  pcd->type = CRED_TYPE_PERMANENT;

  /*
   * These 5 const_cast are allowed because proxy_get_filenames will
   * overwrite the pointers, not the data itself.
   */
  ccaf = NULL;
  cd   = NULL;
  of   = (file.empty() ? NULL : const_cast<char *>(file.c_str()));
  cf   = NULL;
  kf   = NULL;
    
  if (!determine_filenames(&ccaf, &cd, &of, &cf, &kf, 0))
    return 0;

  return destroy_proxy(of, dryrun);
}

static int real_write(int fd, char *buffer, int size)
{
  int written = 0;
  int current = 0;

  do {
    written = write(fd, buffer + current, size - current);
    if (written >= 0) {
      current += written;
    }
  } while ((written > 0) && (current != size));

  return (current == size ? size : -1);
}

int destroy_proxy(char *file, bool dry)
{
  char delblock[100];

  int fd = open(file, O_RDWR);

  if (fd != -1) {
    if (dry) {
      if (!quiet)
	std::cerr << "Would remove " << file << std::endl;
    }
    else {
      memset(delblock, 0, 100);

      int size = lseek(fd, 0L, SEEK_END);
      lseek(fd, 0L, SEEK_SET);
      if (size > 0) {
        int num = size / 100;
        int rem = size % 100;

        while (num--) {
	  (void)real_write(fd, delblock, 100);
	}

        if (rem)
	  (void)real_write(fd, delblock, rem);
      }
      close(fd);
      remove(file);
    }
  }
  else {
    if (!quiet)
      std::cerr << "\nProxy file doesn't exist or has bad permissions\n" << std::endl;
    return 1;
  }

  return 0;
}
