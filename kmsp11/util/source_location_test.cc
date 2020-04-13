#include "kmsp11/util/source_location.h"

#include "gmock/gmock.h"
#include "kmsp11/test/matchers.h"

namespace kmsp11 {
namespace {

TEST(SourceLocationTest, FixedToString) {
  SourceLocation s(42, "/foo/bar/baz.cc");
  EXPECT_EQ(s.ToString(), "baz.cc:42");
}

TEST(SourceLocationTest, MacroLineNumber) {
  // hardcoding a line number would be a better test, but is likely too brittle
  // to be wortwhile.
  int expected = __LINE__ + 1;
  SourceLocation s = SOURCE_LOCATION;
  EXPECT_EQ(s.line(), expected);
}

TEST(SourceLocationTest, MacroFileName) {
  SourceLocation s = SOURCE_LOCATION;
  EXPECT_THAT(s.file_name(), MatchesStdRegex(".*source_location_test.cc"));
}

TEST(SourceLocationTest, MacroToString) {
  // as above, hardcoding a line number would be a better test, but is likely
  // too brittle to be worthwhile.
  int expected_line = __LINE__ + 1;
  SourceLocation s = SOURCE_LOCATION;
  EXPECT_EQ(s.ToString(),
            absl::StrFormat("source_location_test.cc:%d", expected_line));
}

}  // namespace
}  // namespace kmsp11