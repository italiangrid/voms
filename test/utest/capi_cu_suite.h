
#include <cppunit/extensions/HelperMacros.h>
extern "C" {
#include "voms_apic.h"
}

class capi_test : public CppUnit::TestFixture 
{
  CPPUNIT_TEST_SUITE(capi_test);
  CPPUNIT_TEST(VOMS_FindByAlias_case);
  CPPUNIT_TEST(VOMS_FindByVO_case);
  CPPUNIT_TEST(VOMS_DeleteContacts_case);
  CPPUNIT_TEST(VOMS_Init_case);
  CPPUNIT_TEST(VOMS_Copy_case);
  CPPUNIT_TEST(VOMS_CopyAll_case);
  CPPUNIT_TEST(VOMS_Delete_case);
  CPPUNIT_TEST(VOMS_AddTarget_case);
  CPPUNIT_TEST(VOMS_FreeTargets_case);
  CPPUNIT_TEST(VOMS_ListTargets_case);
  CPPUNIT_TEST(VOMS_SetVerificationType_case);
  CPPUNIT_TEST(VOMS_SetLifetime_case);
  CPPUNIT_TEST(VOMS_Destro_case);
  CPPUNIT_TEST(VOMS_ResetOrder_case);
  CPPUNIT_TEST(VOMS_Ordering_case);
  CPPUNIT_TEST(VOMS_Contact_case);
  CPPUNIT_TEST(VOMS_Retrieve_case); 
  CPPUNIT_TEST(VOMS_Import_case);
  CPPUNIT_TEST(VOMS_Export_case);
  CPPUNIT_TEST(VOMS_DefaultData_case);
  CPPUNIT_TEST_SUITE_END();

 private:
  
 public:
  
  void setUp();
  void tearDown();
  void VOMS_Init_case();
  void VOMS_FindByAlias_case();
  void VOMS_FindByVO_case();
  void VOMS_DeleteContacts_case();
  void VOMS_Copy_case();
  void VOMS_CopyAll_case();
  void VOMS_Delete_case();
  void VOMS_AddTarget_case();
  void VOMS_FreeTargets_case();
  void VOMS_ListTargets_case();
  void VOMS_SetVerificationType_case();
  void VOMS_SetLifetime_case();
  void VOMS_Destro_case();
  void VOMS_ResetOrder_case();
  void VOMS_Ordering_case();
  void VOMS_Contact_case();
  void VOMS_Retrieve_case(); 
  void VOMS_Import_case();
  void VOMS_Export_case();
  void VOMS_DefaultData_case();

};
