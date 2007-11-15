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

#include "replace.h"

#include "VOMSServer.h"
#include "dbwrap.h"

#include <exception>
extern "C" {
#include <openssl/ssl.h>
}

int main(int argc, char *argv[])
{
  OpenSSL_add_ssl_algorithms();

  SSL_library_init();
  try
  {
    VOMSServer v(argc,argv);
    v.Run();
  }
  // VOMS specific exception 
  catch(VOMSInitException& e){
    
    std::cout << "Initialization error: " << e.error << std::endl;
    return !0;
  }

  // std::exception
  catch(std::exception& e)
  {
    std::cout << e.what() << std::endl;
  }
  
  catch(...)
  {
    std::cout << "Undefined error." << std::endl;
  }


}
