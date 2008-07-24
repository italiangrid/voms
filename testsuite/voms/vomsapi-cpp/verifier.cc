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
