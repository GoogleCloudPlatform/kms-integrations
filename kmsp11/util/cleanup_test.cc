#include "kmsp11/util/cleanup.h"

#include "gtest/gtest.h"

namespace kmsp11 {
namespace {

TEST(TestCleanup, TestCleanup) {
  int i = 3;
  {
    Cleanup c([&]() { i = 2; });
    EXPECT_EQ(i, 3);
  }
  EXPECT_EQ(i, 2);
}

}  // namespace
}  // namespace kmsp11
