/*********************************************************************
 *
 * Authors: Vincenzo Ciaschini - Vincenzo.Ciaschini@cnaf.infn.it 
 *          Valerio Venturi - Valerio.Venturi@cnaf.infn.it 
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

extern "C" {
#include "config.h"
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/mman.h>
}

#include <string>

#include "vomsclient.h"

int main(int argc, char** argv) {

  struct rlimit newlimit = {0,0};
  if (setrlimit(RLIMIT_CORE, &newlimit) != 0)
    exit(1);

  Client v(argc, argv);
  bool result = v.Run();

  return (result ? 0 : 1);
}
