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
#ifndef VOMS_ERRORS_H
#define VOMS_ERRORS_H

#include <string>

struct errorp {
  int num;
  std::string message;
};

#define ERROR_OFFSET 1000
#define WARN_OFFSET     0

#define WARN_NO_FIRST_SELECT (WARN_OFFSET + 1)
#define WARN_SHORT_VALIDITY  (WARN_OFFSET + 2)
#define WARN_ATTR_SUBSET     (WARN_OFFSET + 3)
#define WARN_UNKNOWN_COMMAND (WARN_OFFSET + 4)

#define ERR_WITH_DB         (ERROR_OFFSET + 3)
#define ERR_NOT_MEMBER      (ERROR_OFFSET + 1)
#define ERR_ATTR_EMPTY      (ERROR_OFFSET + 2)
#define ERR_SUSPENDED       (ERROR_OFFSET + 4)
#define ERR_NO_COMMAND      (ERROR_OFFSET + 5)
#endif
