#include "kmsp11/util/status_macros.h"

#include "absl/status/status.h"
#include "gmock/gmock.h"
#include "kmsp11/test/test_status_macros.h"
#include "kmsp11/util/status_or.h"

namespace kmsp11 {
namespace {

TEST(ReturnIfErrorTest, NoEarlyReturnOnOkStatus) {
  int i = 0;

  absl::Status result = [&i]() -> absl::Status {
    auto okFunc = []() -> absl::Status { return absl::OkStatus(); };
    RETURN_IF_ERROR(okFunc());
    i = 3;
    return absl::OkStatus();
  }();

  EXPECT_OK(result);
  EXPECT_EQ(i, 3);
}

TEST(ReturnIfErrorTest, InvalidArgumentStatus) {
  int i = 0;
  absl::Status result = [&i]() -> absl::Status {
    RETURN_IF_ERROR(absl::NotFoundError("not found"));
    i = 3;
    return absl::OkStatus();
  }();

  EXPECT_THAT(result, StatusIs(absl::StatusCode::kNotFound));
  EXPECT_EQ(i, 0);
}

TEST(ReturnIfErrorTest, ReturnsFromStatusOr) {
  absl::Status s = absl::UnknownError("unknown");
  StatusOr<int> result = [&s]() -> StatusOr<int> {
    RETURN_IF_ERROR(s);
    return 3;
  }();
  EXPECT_THAT(result, StatusIs(absl::StatusCode::kUnknown));
  // It's important that the returned status is equal, and doesn't just have
  // the same code. Message and payload should be equal too.
  EXPECT_EQ(result.status(), s);
}

TEST(AssignOrReturnTest, MutateStateOnOkStatus) {
  int i = 0;
  absl::Status s = [&i]() -> absl::Status {
    ASSIGN_OR_RETURN(i, StatusOr<int>(3));
    return absl::OkStatus();
  }();
  EXPECT_OK(s);
  EXPECT_EQ(i, 3);
}

TEST(AssignOrReturnTest, InitializeStateOnOkStatus) {
  StatusOr<int> s = []() -> StatusOr<int> {
    ASSIGN_OR_RETURN(int j, StatusOr<int>(3));
    return j + 1;
  }();
  EXPECT_OK(s);
  EXPECT_EQ(s.value(), 4);
}

TEST(AssignOrReturnTest, MoveConstructibleIsMoved) {
  auto f = []() -> StatusOr<std::unique_ptr<int>> {
    return absl::make_unique<int>(3);
  };
  StatusOr<int> s = [&f]() -> StatusOr<int> {
    ASSIGN_OR_RETURN(std::unique_ptr<int> i, f());
    return *i;
  }();
  EXPECT_OK(s);
  EXPECT_EQ(s.value(), 3);
}

TEST(AssignOrReturnTest, ReturnOnNonOkStatus) {
  absl::Status s = absl::AbortedError("aborted");
  StatusOr<int> s_or = [&s]() -> StatusOr<int> {
    ASSIGN_OR_RETURN(int i, StatusOr<int>(s));
    return i;
  }();
  EXPECT_THAT(s_or, StatusIs(absl::StatusCode::kAborted));
  // It's important that the returned status is equal, and doesn't just have
  // the same code. Message and payload should be equal too.
  EXPECT_EQ(s_or.status(), s);
}

}  // namespace
}  // namespace kmsp11
