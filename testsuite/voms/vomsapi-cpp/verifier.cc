/*
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
 */
#include "voms_api.h"
#include <stdlib.h>
#include <stdio.h>

#include <string>
#include <vector>
#include <iostream>

int main(int argc, char *argv[]) {
  vomsdata vd;
  int error = 0;
  time_t curtime;
  time(&curtime);

  if (argc != 2) {
    std::cout << "Time offset argument missing." << std::endl;
    exit(1);
  }

  vd.SetVerificationTime(curtime + atoi(argv[1]));
  vd.SetVerificationType(VERIFY_DATE);

  if (vd.RetrieveFromProxy(RECURSE_CHAIN)) {
    std::cout << "Verification succeeded!" << std::endl;
    exit (0);
  }
  else {
    std::cout << "Error Message: " << vd.ErrorMessage() << std::endl;
    exit (0);
  }
}
