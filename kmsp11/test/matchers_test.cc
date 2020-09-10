#include "kmsp11/test/matchers.h"

#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "gmock/gmock.h"
#include "kmsp11/cryptoki.h"
#include "kmsp11/test/test_message.pb.h"

namespace kmsp11 {
namespace {

using ::testing::AllOf;
using ::testing::Eq;
using ::testing::Gt;
using ::testing::HasSubstr;
using ::testing::Lt;
using ::testing::Not;

TEST(MatchesStdRegexTest, MatchesSmokeTest) {
  EXPECT_THAT("foobar_1_2_3@@#baz", MatchesStdRegex("^\\w+.*az$"));
}

TEST(MatchesStdRegexTest, NotMatchesSmokeTest) {
  EXPECT_THAT("foobar_1_2_3@@#baz", Not(MatchesStdRegex("^for.*$")));
}

TEST(MatchesStdRegexTest, StringView) {
  std::string value("abcde");
  EXPECT_THAT(absl::string_view(value), MatchesStdRegex("a\\w+e"));
}

TEST(IsOkTest, OkStatus) { EXPECT_THAT(absl::OkStatus(), IsOk()); }

TEST(IsOkTest, OkStatusOr) { EXPECT_THAT(absl::StatusOr<int>(3), IsOk()); }

TEST(IsOkTest, NotOkStatus) {
  EXPECT_THAT(absl::AbortedError("aborted"), Not(IsOk()));
}

TEST(IsOkTest, NotOkStatusOr) {
  EXPECT_THAT(absl::StatusOr<int>(absl::AbortedError("aborted")), Not(IsOk()));
}

TEST(StatusIsTest, OkStatus) {
  EXPECT_THAT(absl::OkStatus(), StatusIs(absl::StatusCode::kOk));
}

TEST(StatusIsTest, OkStatusOr) {
  EXPECT_THAT(absl::StatusOr<int>(3), StatusIs(absl::StatusCode::kOk));
}

TEST(StatusIsTest, NotOkStatus) {
  EXPECT_THAT(absl::AbortedError("aborted"),
              StatusIs(absl::StatusCode::kAborted));
}

TEST(StatusIsTest, NotOkStatusWithMessage) {
  EXPECT_THAT(absl::AbortedError("aborted"),
              StatusIs(absl::StatusCode::kAborted, HasSubstr("bort")));
}

TEST(StatusIsTest, NotOkStatusOr) {
  EXPECT_THAT(absl::StatusOr<int>(absl::CancelledError("cancelled")),
              StatusIs(absl::StatusCode::kCancelled));
}
TEST(StatusIsTest, NotOkStatusOrWithMessage) {
  EXPECT_THAT(absl::CancelledError("cancelled"),
              StatusIs(absl::StatusCode::kCancelled, Eq("cancelled")));
}

TEST(StatusRvIsTest, OkStatus) {
  EXPECT_THAT(absl::OkStatus(), StatusRvIs(CKR_OK));
}

TEST(StatusRvIsTest, OkStatusOr) {
  EXPECT_THAT(absl::StatusOr<int>(3), StatusRvIs(CKR_OK));
}

TEST(StatusRvIsTest, DefaultNotOkStatus) {
  EXPECT_THAT(absl::AbortedError("aborted"), StatusRvIs(kDefaultErrorCkRv));
}

TEST(StatusRvIsTest, DefaultNotOkStatusOr) {
  EXPECT_THAT(absl::StatusOr<int>(absl::CancelledError("cancelled")),
              StatusRvIs(kDefaultErrorCkRv));
}

TEST(StatusRvIsTest, CustomNotOkStatus) {
  absl::Status status = absl::AbortedError("aborted");
  SetErrorRv(status, CKR_DEVICE_ERROR);
  EXPECT_THAT(status, StatusRvIs(CKR_DEVICE_ERROR));
}

TEST(StatusRvIsTest, CustomNotOkStatusOr) {
  absl::Status s = absl::CancelledError("cancelled");
  SetErrorRv(s, CKR_HOST_MEMORY);
  EXPECT_THAT(absl::StatusOr<int>(s), StatusRvIs(CKR_HOST_MEMORY));
}

TEST(StatusRvIsTest, InnerMatcher) {
  absl::Status s = absl::CancelledError("cancelled");
  SetErrorRv(s, CKR_DATA_LEN_RANGE);
  EXPECT_THAT(
      s, StatusRvIs(testing::AnyOf(CKR_FUNCTION_FAILED, CKR_DATA_LEN_RANGE)));
}

TEST(EqualsProtoTest, Equals) {
  TestMessage m1;
  m1.set_string_value("foo");

  TestMessage m2;
  m2.set_string_value("foo");

  EXPECT_THAT(m1, EqualsProto(m2));
}

TEST(EqualsProtoTest, NotEquals) {
  TestMessage m1;
  m1.set_string_value("foo");

  TestMessage m2;
  m2.set_string_value("bar");

  EXPECT_THAT(m1, Not(EqualsProto(m2)));
}

TEST(IsOkAndHoldsTest, MatchesValue) {
  absl::StatusOr<int> s(3);
  EXPECT_THAT(s, IsOkAndHolds(3));
}

TEST(IsOkAndHoldsTest, MatchesMatcher) {
  absl::StatusOr<int> s(3);
  EXPECT_THAT(s, IsOkAndHolds(AllOf(Gt(2), Lt(5))));
}

TEST(IsOkAndHoldsTest, DoesNotMatch) {
  absl::StatusOr<int> s(3);
  EXPECT_THAT(s, Not(IsOkAndHolds(4)));
}

TEST(IsOkAndHoldsTest, IsNotOk) {
  absl::StatusOr<int> s(absl::AbortedError("aborted"));
  EXPECT_THAT(s, Not(IsOkAndHolds(3)));
}

}  // namespace
}  // namespace kmsp11
