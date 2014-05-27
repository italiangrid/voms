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

#include "config.h"

#include "replace.h"

#include "VOMSServer.h"
#include "dbwrap.h"

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
  catch(voms_init_error& e)
  {
    std::cout << "Initialization error: " << e.what() << std::endl;
    exit(1);
  }
  catch(std::exception& e)
  {
    std::cout << "Error: " << e.what() << std::endl;
    exit(1);
  }
  catch(...)
  {
    std::cout << "Undefined error." << std::endl;
    exit(1);
  }

  exit(0);

}
