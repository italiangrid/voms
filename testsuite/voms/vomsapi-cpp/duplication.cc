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
  vomsdata va;
  int error = 0;

  if (va.RetrieveFromProxy(RECURSE_CHAIN)) {
    vomsdata vd (va);
    int total = 0;
    int count = 0;

    /* now we have parsed and verified the data */
    std::vector<voms> vomsarray = vd.data;

    total = vomsarray.size();


    if (argc == 2 && !strcmp(argv[1], "total"))
      std::cout << "total: " << total <<"\n";

    if (argc == 1 || !strcmp(argv[1], "voname1"))
      printf("voname1: %s\n", vomsarray[0].voname.c_str());

    if (argc == 1 || !strcmp(argv[1], "user1"))
      printf("user1: %s\n", vomsarray[0].user.c_str());

    if (argc == 1 || !strcmp(argv[1], "userca1"))
      printf("userca1: %s\n", vomsarray[0].userca.c_str());

    if (argc == 1 || !strcmp(argv[1], "server1"))
      printf("server1: %s\n", vomsarray[0].server.c_str());

    if (argc == 1 || !strcmp(argv[1], "serverca1"))
      printf("serverca1: %s\n", vomsarray[0].serverca.c_str());

    if (argc == 1 || !strcmp(argv[1], "uri1"))
      printf("uri1: %s\n", vomsarray[0].uri.c_str()); 
      
    if (argc == 1 || !strcmp(argv[1], "begdate1"))
      printf("begdate1: %s\n", vomsarray[0].date1.c_str());

    if (argc == 1 || !strcmp(argv[1], "enddate1"))
      printf("enddate1: %s\n", vomsarray[0].date2.c_str());

    if (argc == 1 || !strcmp(argv[1], "fqan1")) {
      std::vector<std::string> fqans = vomsarray[0].fqan;
      int index = 0;
      for (index = 0; index < fqans.size(); index ++)
        printf("fqan1: %s\n", fqans[index].c_str());
    }

    if (argc == 1 || !strcmp(argv[1], "version1"))
      printf("version1: %ld\n", (long int)vomsarray[0].version);

      


    if ((argc == 1 || !strcmp(argv[1], "voname2")) && total == 2)
      printf("voname2: %s\n", vomsarray[1].voname.c_str());

    if ((argc == 1 || !strcmp(argv[1], "user2")) && total == 2)
      printf("user2: %s\n", vomsarray[1].user.c_str());

    if ((argc == 1 || !strcmp(argv[1], "userca2"))  && total == 2)
      printf("userca2: %s\n", vomsarray[1].userca.c_str());

    if ((argc == 1 || !strcmp(argv[1], "server2")) && total == 2)
      printf("server2: %s\n", vomsarray[1].server.c_str());

    if ((argc == 1 || !strcmp(argv[1], "serverca2")) && total == 2)
      printf("serverca2: %s\n", vomsarray[1].serverca.c_str());

    if ((argc == 1 || !strcmp(argv[1], "uri2")) && total == 2)
      printf("uri2: %s\n", vomsarray[1].uri.c_str());

    if ((argc == 1 || !strcmp(argv[1], "begdate2")) && total == 2)
      printf("begdate2: %s\n", vomsarray[1].date1.c_str());

    if ((argc == 1 || !strcmp(argv[1], "enddate2")) && total == 2)
      printf("enddate2: %s\n", vomsarray[1].date2.c_str());

    if ((argc == 1 || !strcmp(argv[1], "fqan2")) &&total == 2) {
      std::vector<std::string> fqans = vomsarray[1].fqan;
      int index = 0;
      for (index = 0; index < fqans.size(); index ++)
        printf("fqan2: %s\n", fqans[index].c_str());
    }
    
    if ((argc == 1 || !strcmp(argv[1], "version2")) && total == 2)
      printf("version2: %ld\n", (long int)vomsarray[1].version);

    exit (0);
  }
  else {
    std::cerr << "Error Message2: " << va.ErrorMessage() << "\n";
    exit (1);
  }
}
