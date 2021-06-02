/*
 * Copyright 2021 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef KMSP11_TEST_TEST_STATUS_MACROS_H_
#define KMSP11_TEST_TEST_STATUS_MACROS_H_

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_format.h"
#include "glog/logging.h"
#include "gmock/gmock.h"
#include "kmsp11/test/matchers.h"
#include "kmsp11/util/status_macros.h"
#include "kmsp11/util/status_utils.h"

// Macros for testing the results of functions that return a status.
#define EXPECT_OK(expr) EXPECT_THAT(::kmsp11::ToStatus(expr), ::kmsp11::IsOk());
#define ASSERT_OK(expr) ASSERT_THAT(::kmsp11::ToStatus(expr), ::kmsp11::IsOk());
#define CHECK_OK(expr)                                  \
  do {                                                  \
    ::absl::Status __status = ::kmsp11::ToStatus(expr); \
    CHECK(__status.ok()) << __status << " is not OK";   \
  } while (0);

// Implementation for ASSERT_OK_AND_ASSIGN, declared below.
#define ASSERT_OK_AND_ASSIGN_IMPL(var, lhs, rexpr) \
  auto var = (rexpr);                              \
  ASSERT_OK(var.status());                         \
  lhs = std::move(var).value();

// Executes an expression that returns a absl::StatusOr, and assigns the
// contained variable to lhs if the error code is OK.
// If the Status is non-OK, generates a test failure and returns from the
// current function, which must have a void return type.
//
// Example: Declaring and initializing a new value
//   ASSERT_OK_AND_ASSIGN(const ValueType& value, MaybeGetValue(arg));
//
// Example: Assigning to an existing value
//   ValueType value;
//   ASSERT_OK_AND_ASSIGN(value, MaybeGetValue(arg));
//
// The value assignment example would expand into something like:
//   auto status_or_value = MaybeGetValue(arg);
//   ASSERT_OK(status_or_value.status());
//   value = std::move(status_or_value).ValueOrDie();
//
// WARNING: Like ASSIGN_OR_RETURN, ASSERT_OK_AND_ASSIGN expands into multiple
//   statements; it cannot be used in a single statement (e.g. as the body of
//   an if statement without {})!
#define ASSERT_OK_AND_ASSIGN(lhs, rexpr)                                      \
  ASSERT_OK_AND_ASSIGN_IMPL(STATUS_CONCAT_NAME(_status_or, __COUNTER__), lhs, \
                            rexpr);

#endif  // KMSP11_TEST_TEST_STATUS_MACROS_H_
