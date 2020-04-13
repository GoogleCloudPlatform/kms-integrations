#include "kmsp11/test/matchers.h"

#include "gmock/gmock.h"
#include "gtest/gtest-spi.h"

namespace kmsp11 {
namespace {

using ::testing::Not;

TEST(MatchesStdRegexTest, MatchesSmokeTest) {
  EXPECT_THAT("foobar_1_2_3@@#baz", MatchesStdRegex("^\\w+.*az$"));
}

TEST(MatchesStdRegexTest, NotMatchesSmokeTest) {
  EXPECT_THAT("foobar_1_2_3@@#baz", Not(MatchesStdRegex("^for.*$")));
}

TEST(IsOkTest, OkStatus) { EXPECT_THAT(absl::OkStatus(), IsOk()); }

TEST(IsOkTest, NotOkStatus) {
  EXPECT_THAT(absl::AbortedError("aborted"), Not(IsOk()));
}

TEST(StatusIsTest, OkStatus) {
  EXPECT_THAT(absl::OkStatus(), StatusIs(absl::StatusCode::kOk));
}

TEST(StatusIsTest, NotOkStatus) {
  EXPECT_THAT(absl::AbortedError("aborted"),
              StatusIs(absl::StatusCode::kAborted));
}

TEST(ExpectOkTest, OkStatus) { EXPECT_OK(absl::OkStatus()); }

TEST(ExpectOkTest, NotOkStatus) {
  EXPECT_NONFATAL_FAILURE(EXPECT_OK(absl::UnknownError("foo")), "UNKNOWN: foo");
}

TEST(AssertOkTest, OkStatus) { ASSERT_OK(absl::OkStatus()); }

TEST(AssertOkTest, NotOkStatus) {
  EXPECT_FATAL_FAILURE(ASSERT_OK(absl::NotFoundError("foo")), "NOT_FOUND: foo");
}

}  // namespace
}  // namespace kmsp11
