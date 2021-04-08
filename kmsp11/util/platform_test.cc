#include "kmsp11/util/platform.h"

#include "gmock/gmock.h"

namespace kmsp11 {
namespace {

using ::testing::HasSubstr;
using ::testing::Not;

TEST(PlatformTest, HostPlatformInfoIsKnown) {
  EXPECT_THAT(GetHostPlatformInfo(), Not(HasSubstr("unknown")));
}

}  // namespace
}  // namespace kmsp11