#ifndef KMSP11_TEST_PROTO_PARSER_H_
#define KMSP11_TEST_PROTO_PARSER_H_

#include "google/protobuf/text_format.h"
#include "gtest/gtest.h"

namespace kmsp11 {

// A helper for parsing a text format protobuf message, and converting it on
// demand to a desired type. Conversion EXPECT fails if the provided string
// cannot be parsed as the requested type.
class ParseProtoHelper {
 public:
  ParseProtoHelper(std::string text) : text_(text) {}

  template <class T>
  inline operator T() {
    T message;
    EXPECT_TRUE(google::protobuf::TextFormat::ParseFromString(text_, &message))
        << "failure parsing textproto";
    return message;
  }

 private:
  const std::string text_;
};

inline ParseProtoHelper ParseTestProto(std::string text) {
  return ParseProtoHelper(text);
}

}  // namespace kmsp11

#endif  // KMSP11_TEST_PROTO_PARSER_H_
