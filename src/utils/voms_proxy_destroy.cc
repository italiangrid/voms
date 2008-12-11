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
//const std::string VERSION         = "0.1";

extern "C" {
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
  //#include <getopt.h>
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

    static char *LONG_USAGE = \
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

int destroy_proxy(char *file, bool dry)
{
  char *delblock[100];
  
  if (dry)
    std::cerr << "Would remove " << file << std::endl;
  else {
    for (int i = 0; i <100; i++)
      delblock[i] = '\0';

    int fd = open(file, O_RDWR);
    if (fd != -1) {
      int size = lseek(fd, 0L, SEEK_END);
      lseek(fd, 0L, SEEK_SET);
      if (size > 0) {
        int num = size / 100;
        int rem = size % 100;

        while (num--) 
          write(fd,delblock,100);
        if (rem)
          write(fd, delblock, rem);
      }
      close(fd);
      remove(file);
    }
    else {
      printf("\nProxy file doesn't exist or has bad permissions\n\n");
      return 1;
    }
    
    return 0;
  }
  return 0;
}
