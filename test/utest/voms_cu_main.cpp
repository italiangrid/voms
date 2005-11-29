#include <cppunit/TestResult.h>
#include <cppunit/TestRunner.h>
#include <cppunit/TestResultCollector.h>
#include <cppunit/TextOutputter.h>
#include <iostream>

#include <voms_cu_suite.h>

int main(int argc, char ** argv)
{

  CppUnit::TestResult controller;
  CppUnit::TestResultCollector result;

  controller.addListener(&result);
  CppUnit::TestRunner runner;

  runner.addTest(voms_test::suite());
  runner.run(controller);

  CppUnit::TextOutputter outputter(&result, std::cerr);
  outputter.write();

  return (result.wasSuccessful() ? 0 : 1);
}
