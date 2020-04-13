#include "kmsp11/util/status_or.h"

#include "gmock/gmock.h"

namespace kmsp11 {
namespace {

TEST(StatusOrTest, TChoiceCopyConstructible) {
  StatusOr<int> result_or = 3;
  EXPECT_EQ(result_or.value(), 3);
}

TEST(StatusOrTest, TChoiceMoveConstructible) {
  StatusOr<std::unique_ptr<int>> result_or = absl::make_unique<int>(3);
  EXPECT_EQ(*result_or.value().get(), 3);
}

TEST(StatusOrTest, TChoiceIsOK) {
  StatusOr<int> result_or = 3;
  EXPECT_TRUE(result_or.ok());
}

TEST(StatusOrTest, TChoiceMoveOut) {
  StatusOr<std::unique_ptr<int>> result_or = absl::make_unique<int>(3);
  std::unique_ptr<int> result = std::move(result_or).value();
  EXPECT_EQ(*result.get(), 3);
}

TEST(StatusOrTest, StatusChoiceDeathOnOkStatus) {
  EXPECT_DEATH(StatusOr<int> s = absl::OkStatus(), "StatusOr from OK status");
}

TEST(StatusOrTest, StatusChoiceReturnsStatus) {
  absl::Status s = absl::InvalidArgumentError("invalid argument: foo");
  StatusOr<int> s_or = s;
  EXPECT_EQ(s_or.status(), s);
}

TEST(StatusOrTest, StatusChoiceDeathOnValueRef) {
  StatusOr<int> s_or = absl::AbortedError("gave up");
  EXPECT_DEATH(s_or.value(), "retrieve value from non-OK StatusOr");
}

TEST(StatusOrTest, StatusChoiceDeathOnRvalueRef) {
  StatusOr<std::unique_ptr<int>> s_or = absl::AbortedError("gave up");
  EXPECT_DEATH(std::move(s_or).value(), "retrieve value from non-OK StatusOr");
}

}  // namespace
}  // namespace kmsp11
