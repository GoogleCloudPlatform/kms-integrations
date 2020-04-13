#include "kmsp11/util/status_utils.h"

#include "absl/status/status.h"
#include "gtest/gtest.h"

namespace kmsp11 {
namespace {

TEST(SetErrorRvTest, SetErrorRvOnErrorStatus) {
  absl::Status s = absl::ResourceExhaustedError("foo");
  EXPECT_NO_FATAL_FAILURE(SetErrorRv(s, CKR_INFORMATION_SENSITIVE));
}

TEST(SetErrorRvTest, SetErrorRvOnOkStatus) {
  absl::Status s = absl::OkStatus();
  EXPECT_DEATH(SetErrorRv(s, CKR_ARGUMENTS_BAD),
               "attempting to set rv=7 for status OK");
}

TEST(SetErrorRvTest, SetOkRvOnErrorStatus) {
  absl::Status s = absl::OutOfRangeError("bar");
  EXPECT_DEATH(SetErrorRv(s, CKR_OK),
               "attempting to set rv=0 for status OUT_OF_RANGE");
}

TEST(SetErrorRvTest, SetOkRvOnOkStatus) {
  absl::Status s = absl::OkStatus();
  EXPECT_DEATH(SetErrorRv(s, CKR_OPERATION_NOT_INITIALIZED),
               "attempting to set rv=145 for status OK");
}

TEST(SetErrorRvTest, OkStatus) {
  absl::Status s = absl::OkStatus();
  EXPECT_EQ(GetCkRv(s), CKR_OK);
}

TEST(GetCkRvTest, DefaultError) {
  EXPECT_EQ(GetCkRv(absl::AbortedError("foo")), CKR_FUNCTION_FAILED);
}

TEST(GetCkRvTest, RetrieveSetValue) {
  absl::Status s = absl::UnknownError("foo");
  SetErrorRv(s, CKR_ATTRIBUTE_TYPE_INVALID);
  EXPECT_EQ(GetCkRv(s), CKR_ATTRIBUTE_TYPE_INVALID);
}

TEST(GetCkRvTest, RetrieveVendorDefinedSetValue) {
  CK_RV custom_value = CKR_VENDOR_DEFINED | 0x1E100;
  absl::Status s = absl::UnknownError("foo");
  SetErrorRv(s, custom_value);
  EXPECT_EQ(GetCkRv(s), custom_value);
}

}  // namespace
}  // namespace kmsp11
