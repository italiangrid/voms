
#include <cppunit/extensions/HelperMacros.h>
#include "voms_api.h"

#include <iostream>

class vomsdata_test : public CppUnit::TestFixture 
{
  CPPUNIT_TEST_SUITE(vomsdata_test);
  CPPUNIT_TEST(AddTarget_case);
  CPPUNIT_TEST(FindByAlias_case);
  CPPUNIT_TEST(FindByVO_case);
  CPPUNIT_TEST(Contact_case);
  CPPUNIT_TEST(Retrieve_case);
  CPPUNIT_TEST(Import_case);
  CPPUNIT_TEST_SUITE_END();

 private:
  
  std::string userconf;
  std::string name;
  std::string nick;
  vomsdata v;
  
  std::string buffer;

 public:
  
  void setUp();
  void tearDown();
  void AddTarget_case();
  void FindByAlias_case();
  void FindByVO_case();
  void Contact_case();
  void Retrieve_case();
  void Import_case();

};
