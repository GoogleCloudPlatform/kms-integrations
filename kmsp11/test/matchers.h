#ifndef KMSP11_TEST_MATCHERS_H_
#define KMSP11_TEST_MATCHERS_H_

#include <regex>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_format.h"
#include "gmock/gmock.h"
#include "google/protobuf/util/message_differencer.h"
#include "kmsp11/util/status_utils.h"

namespace kmsp11 {

// A regex matcher with the same signature as ::testing::MatchesRegex, but whose
// implementation is backed by std::regex.
//
// Unfortunately ::testing::MatchesRegex does not operate consistently across
// platforms:
// https://github.com/google/googletest/blob/master/googletest/docs/advanced.md#regular-expression-syntax
MATCHER_P(MatchesStdRegex, pattern,
          absl::StrFormat("%s regex '%s'",
                          (negation ? "doesn't match" : "matches"),
                          testing::PrintToString(pattern))) {
  return std::regex_match(std::string(arg), std::regex(pattern));
}

// Tests that the supplied status has the expected status code.
MATCHER_P(StatusIs, status_code,
          absl::StrFormat("status is %s%s", (negation ? "not " : ""),
                          testing::PrintToString(status_code))) {
  return ToStatus(arg).code() == status_code;
}

// Tests that the supplied status has the expected status code and has a message
// that matches the supplied message matcher.
MATCHER_P2(
    StatusIs, status_code, message_matcher,
    negation ? absl::StrFormat(
                   "is a status whose code is not %d or has a message that %s",
                   status_code,
                   testing::DescribeMatcher<absl::string_view>(message_matcher,
                                                               true))
             : absl::StrFormat(
                   "is a status whose code is %d and has a message that %s",
                   status_code,
                   testing::DescribeMatcher<absl::string_view>(message_matcher,
                                                               false))) {
  absl::Status status = ToStatus(arg);
  return status.code() == status_code &&
         testing::ExplainMatchResult(message_matcher, status.message(),
                                     result_listener);
}

// Tests that the supplied status has the expected CK_RV.
MATCHER_P(StatusRvIs, ck_rv_matcher,
          absl::StrCat("status ck_rv matches ",
                       testing::DescribeMatcher<CK_RV>(ck_rv_matcher,
                                                       negation))) {
  return testing::ExplainMatchResult(ck_rv_matcher, GetCkRv(ToStatus(arg)),
                                     result_listener);
}

// Tests that the supplied status is OK.
MATCHER(IsOk, absl::StrFormat("status is %sOK", negation ? "not " : "")) {
  return ToStatus(arg).ok();
}

// Tests that the supplied protocol buffer message is equal.
MATCHER_P(EqualsProto, proto,
          absl::StrFormat("proto %s", negation ? "does not equal" : "equals")) {
  return google::protobuf::util::MessageDifferencer::Equals(arg, proto);
}

// Tests that the supplied absl::StatusOr is OK and has a value that matches the
// provided matcher.
MATCHER_P(IsOkAndHolds, matcher, "") {
  if (!arg.ok()) {
    return false;
  }
  return testing::ExplainMatchResult(matcher, arg.value(), result_listener);
}

}  // namespace kmsp11

#endif  // KMSP11_TEST_MATCHERS_H_
