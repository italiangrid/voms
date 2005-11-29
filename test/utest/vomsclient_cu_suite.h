
#include <cppunit/extensions/HelperMacros.h>
#include "vomsclient.h"

class vomsclient_test : public CppUnit::TestFixture 
{
  CPPUNIT_TEST_SUITE(vomsclient_test);
  CPPUNIT_TEST(Run_case);
  CPPUNIT_TEST_SUITE_END();

 private:
  
 public:
  
  void setUp();
  void tearDown();
  void Run_case();
  
};
