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
#include <string.h>

#include <string>
#include <vector>
#include <iostream>

int main(int argc, char *argv[]) {
  vomsdata vd;
  int error = 0;

  if (vd.RetrieveFromProxy(RECURSE_CHAIN)) {
    int total = 0;
    int count = 0;

    /* now we have parsed and verified the data */
    std::vector<voms> vomsarray = vd.data;
    voms v;

    if (vd.DefaultData(v)) {
      printf("voname1: %s\n", v.voname.c_str());
      printf("user1: %s\n", v.user.c_str());
      printf("userca1: %s\n", v.userca.c_str());
      printf("server1: %s\n", v.server.c_str());
      printf("serverca1: %s\n", v.serverca.c_str());
      printf("uri1: %s\n", v.uri.c_str()); 
      printf("begdate1: %s\n", v.date1.c_str());
      printf("enddate1: %s\n", v.date2.c_str());
      std::vector<std::string> fqans = v.fqan;

      for (int index = 0; index < fqans.size(); index ++)
        printf("fqan1: %s\n", fqans[index].c_str());

      printf("version1: %d\n", v.version);
      
      exit (0);
    }
  }
  std::cerr << "Error Message2: " << vd.ErrorMessage() << "\n";
  exit(1);
}
