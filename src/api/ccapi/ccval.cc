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
extern "C" {
#include "config.h"
#include "replace.h"
}

#include <string>
#include <vector>

#include "voms_api.h"

extern "C" {
#include <openssl/x509.h>
#include "newformat.h"
#include "listfunc.h"
}


#include "realdata.h"
#include "validate.h"

bool vomsdata::verifyac(X509 *cert, X509 *issuer, AC *ac, time_t verificationtime, voms &v)
{
  int result;
  struct realdata *rd = (struct realdata *)v.realdata;

  delete rd->attributes;
  AC_free(rd->ac);

  rd->ac = NULL;
  rd->attributes = NULL;

  rd->attributes = new std::vector<attributelist>;

  try {
    result = validate(cert, issuer, ac, v, ver_type, verificationtime, rd);
  }
  catch (std::bad_alloc& e) {
    seterror(VERR_MEM, "Out of Memory");
    return false;
  }

  if (result)
    seterror(VERR_VERIFY, get_error(result));

  return result == 0;
}
