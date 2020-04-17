#include "kmsp11/main/bridge.h"

#include "gmock/gmock.h"
#include "kmsp11/test/matchers.h"
#include "kmsp11/test/test_status_macros.h"

namespace kmsp11 {
namespace {

TEST(InitializeTest, InitializeFinalize) {
  EXPECT_OK(Initialize(nullptr));
  EXPECT_OK(Finalize(nullptr));
}

TEST(InitializeTest, FailsOnSecondInitialize) {
  EXPECT_OK(Initialize(nullptr));
  EXPECT_THAT(Initialize(nullptr),
              StatusRvIs(CKR_CRYPTOKI_ALREADY_INITIALIZED));
  // Finalize so that other tests see an uninitialized state
  EXPECT_OK(Finalize(nullptr));
}

TEST(FinalizeTest, FailsWithoutInitialize) {
  EXPECT_THAT(Finalize(nullptr), StatusRvIs(CKR_CRYPTOKI_NOT_INITIALIZED));
}

TEST(GetInfoTest, Success) {
  EXPECT_OK(Initialize(nullptr));
  CK_INFO info;
  EXPECT_OK(GetInfo(&info));
  EXPECT_OK(Finalize(nullptr));
}

TEST(GetInfoTest, FailsWithoutInitialize) {
  EXPECT_THAT(GetInfo(nullptr), StatusRvIs(CKR_CRYPTOKI_NOT_INITIALIZED));
}

TEST(GetFunctionListTest, Success) {
  CK_FUNCTION_LIST* function_list;
  EXPECT_OK(GetFunctionList(&function_list));
}

TEST(GetFunctionListTest, FunctionListValidPointers) {
  CK_FUNCTION_LIST* f;
  EXPECT_OK(GetFunctionList(&f));
  EXPECT_EQ(f->C_Initialize(nullptr), CKR_OK);
  CK_INFO info;
  EXPECT_EQ(f->C_GetInfo(&info), CKR_OK);
  EXPECT_EQ(f->C_Finalize(nullptr), CKR_OK);
}

}  // namespace
}  // namespace kmsp11
