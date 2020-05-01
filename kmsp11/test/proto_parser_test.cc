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
