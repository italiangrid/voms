
#include "vomsclient_cu_suite.h"

#include <iostream>

void vomsclient_test::setUp() 
{
  std::cout << std::endl << "Starting up ..." << std::endl;
}

void vomsclient_test::tearDown() 
{
  std::cout << "Tearing down ..." << std::endl;
}

void vomsclient_test::Run_case()
{
  char ** argv = (char **)malloc(1 * sizeof(char *));
  argv[0] = (char *)malloc(strlen("voms-proxy-init")*sizeof(char));
  argv[0] = "voms_proxy-init";

  Client c(1, argv);
  CPPUNIT_ASSERT(c.Run());
}
