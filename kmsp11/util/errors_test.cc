#include "kmsp11/util/errors.h"

#include "gtest/gtest.h"
#include "kmsp11/test/matchers.h"

namespace kmsp11 {
namespace {

TEST(NewErrorTest, ErrorCodeMatches) {
  EXPECT_THAT(NewError(absl::StatusCode::kPermissionDenied, "",
                       CKR_BUFFER_TOO_SMALL, SOURCE_LOCATION),
              StatusIs(absl::StatusCode::kPermissionDenied));
}

TEST(NewErrorTest, FailureOnOkStatus) {
  EXPECT_DEATH(absl::Status s = NewError(absl::StatusCode::kOk, "",
                                         CKR_BUFFER_TOO_SMALL, SOURCE_LOCATION),
               "cannot be called with code=OK");
}

TEST(NewErrorTest, MessageMatches) {
  absl::Status status = NewError(absl::StatusCode::kAborted, "foobarbaz",
                                 CKR_BUFFER_TOO_SMALL, SOURCE_LOCATION);
  EXPECT_THAT(status.message(), MatchesStdRegex(".*foobarbaz.*"));
}

TEST(NewErrorTest, CkRvMatches) {
  absl::Status status =
      NewError(absl::StatusCode::kAborted, "", CKR_PIN_LOCKED, SOURCE_LOCATION);
  EXPECT_EQ(GetCkRv(status), CKR_PIN_LOCKED);
}

TEST(NewErrorTest, FailureOnCkrOk) {
  EXPECT_DEATH(absl::Status s = NewError(absl::StatusCode::kAborted,
                                         "foobarbaz", CKR_OK, SOURCE_LOCATION),
               "cannot be called with ck_rv=CKR_OK");
}

TEST(NewErrorTest, SourceLocationIncluded) {
  SourceLocation s(42, "/path/to/file.cc");
  absl::Status status =
      NewError(absl::StatusCode::kAborted, "message", CKR_PIN_LOCKED, s);
  EXPECT_THAT(status.message(), MatchesStdRegex(".*" + s.ToString() + ".*"));
}

}  // namespace
}  // namespace kmsp11
