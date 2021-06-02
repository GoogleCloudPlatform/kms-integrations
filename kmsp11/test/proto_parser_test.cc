// Copyright 2021 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "kmsp11/test/proto_parser.h"

#include "gmock/gmock.h"
#include "gtest/gtest-spi.h"
#include "kmsp11/test/matchers.h"
#include "kmsp11/test/test_message.pb.h"

namespace kmsp11 {
namespace {

TEST(ParseProtoTest, ParseTestMessage) {
  TestMessage msg;
  msg.set_string_value("foo bar baz");
  msg.set_int32_value(1337);

  TestMessage expected = ParseTestProto(R"(
    string_value: "foo bar baz"
    int32_value: 1337
  )");

  EXPECT_THAT(msg, EqualsProto(expected));
}

TEST(ParseProtoTest, ParseMalformedMessage) {
  TestMessage t;
  auto f = [&]() { t = ParseTestProto("x: 12"); };
  EXPECT_NONFATAL_FAILURE(f(), "failure parsing textproto");
  EXPECT_THAT(t, EqualsProto(TestMessage()));
}

}  // namespace
}  // namespace kmsp11
