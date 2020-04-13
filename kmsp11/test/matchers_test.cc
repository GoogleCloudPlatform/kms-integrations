#include "kmsp11/test/matchers.h"

#include "gmock/gmock.h"
#include "kmsp11/util/status_or.h"

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

TEST(IsOkTest, OkStatusOr) { EXPECT_THAT(StatusOr<int>(3), IsOk()); }

TEST(IsOkTest, NotOkStatus) {
  EXPECT_THAT(absl::AbortedError("aborted"), Not(IsOk()));
}

TEST(IsOkTest, NotOkStatusOr) {
  EXPECT_THAT(StatusOr<int>(absl::AbortedError("aborted")), Not(IsOk()));
}

TEST(StatusIsTest, OkStatus) {
  EXPECT_THAT(absl::OkStatus(), StatusIs(absl::StatusCode::kOk));
}

TEST(StatusIsTest, OkStatusOr) {
  EXPECT_THAT(StatusOr<int>(3), StatusIs(absl::StatusCode::kOk));
}

TEST(StatusIsTest, NotOkStatus) {
  EXPECT_THAT(absl::AbortedError("aborted"),
              StatusIs(absl::StatusCode::kAborted));
}

TEST(StatusIsTest, NotOkStatusOr) {
  EXPECT_THAT(StatusOr<int>(absl::CancelledError("cancelled")),
              StatusIs(absl::StatusCode::kCancelled));
}

}  // namespace
}  // namespace kmsp11
