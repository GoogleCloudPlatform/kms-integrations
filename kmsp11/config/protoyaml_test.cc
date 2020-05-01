#include "kmsp11/config/protoyaml.h"

#include "gmock/gmock.h"
#include "kmsp11/config/protoyaml_test.pb.h"
#include "kmsp11/test/proto_parser.h"
#include "kmsp11/test/test_status_macros.h"

namespace kmsp11 {
namespace {

using ::testing::ElementsAre;
using ::testing::HasSubstr;

TEST(ProtoyamlTest, ParseEmpty) {
  YAML::Node node = YAML::Load("");
  Scalars result;
  EXPECT_OK(YamlToProto(node, &result));
  EXPECT_THAT(result, EqualsProto(Scalars()));
}

TEST(ProtoyamlTest, ParseString) {
  YAML::Node node = YAML::Load("string_field: foo");
  Scalars result;
  EXPECT_OK(YamlToProto(node, &result));
  EXPECT_EQ(result.string_field(), "foo");
}

TEST(ProtoyamlTest, ParseInt) {
  YAML::Node node = YAML::Load("int_field: 31337");
  Scalars result;
  EXPECT_OK(YamlToProto(node, &result));
  EXPECT_EQ(result.int_field(), 31337);
}

TEST(ProtoyamlTest, ParseTrue) {
  YAML::Node node = YAML::Load("bool_field: true");
  Scalars result;
  EXPECT_OK(YamlToProto(node, &result));
  EXPECT_TRUE(result.bool_field());
}

TEST(ProtoyamlTest, ParseFalse) {
  YAML::Node node = YAML::Load("bool_field: false");
  Scalars result;
  EXPECT_OK(YamlToProto(node, &result));
  EXPECT_FALSE(result.bool_field());
}

TEST(ProtoyamlTest, CombinedWithDefaults) {
  YAML::Node node = YAML::Load("bool_field: false");
  Scalars result = ParseTestProto("int_field: 123");
  EXPECT_OK(YamlToProto(node, &result));
  EXPECT_THAT(result, EqualsProto<Scalars>(ParseTestProto(R"(
    bool_field: false
    int_field: 123
  )")));
}

TEST(ProtoyamlTest, FailsOnUnknownField) {
  YAML::Node node = YAML::Load("foo_field: foo");
  Scalars result;
  absl::Status status = YamlToProto(node, &result);
  EXPECT_THAT(status, StatusIs(absl::StatusCode::kInvalidArgument));
  EXPECT_THAT(status.message(), HasSubstr("unrecognized key: foo_field"));
}

TEST(ProtoyamlTest, ErrorMessageContainsLocation) {
  YAML::Node node = YAML::Load(R"(---
string_field: foo
nota_field: bar
)");

  Scalars result;
  absl::Status status = YamlToProto(node, &result);
  EXPECT_THAT(status, StatusIs(absl::StatusCode::kInvalidArgument));
  EXPECT_THAT(status.message(), HasSubstr("line 2, column 0"));
}

TEST(ProtoyamlTest, MultipleDefinition) {
  YAML::Node node = YAML::Load(R"(---
string_field: foo
string_field: bar
)");

  Scalars result;
  absl::Status status = YamlToProto(node, &result);
  EXPECT_THAT(status, StatusIs(absl::StatusCode::kInvalidArgument));
  EXPECT_THAT(status.message(), HasSubstr("string_field is multiply defined"));
}

TEST(ProtoyamlTest, RepeatedStringInternalError) {
  YAML::Node node = YAML::Load(R"(---
strings:
  - foo
  - bar
)");

  RepeatedString result;
  absl::Status status = YamlToProto(node, &result);
  EXPECT_THAT(status, StatusIs(absl::StatusCode::kInternal));
  EXPECT_THAT(status.message(), HasSubstr("repeated string"));
}

TEST(ProtoyamlTest, SimpleFieldInComplexMessage) {
  YAML::Node node = YAML::Load("root_field: foo");
  NestedScalars result;
  EXPECT_OK(YamlToProto(node, &result));
  EXPECT_EQ(result.root_field(), "foo");
}

TEST(ProtoyamlTest, NestedMessage) {
  YAML::Node node = YAML::Load(R"(---
scalars:
  bool_field: true
  string_field: bar
)");

  NestedScalars result;
  EXPECT_OK(YamlToProto(node, &result));

  NestedScalars want = ParseTestProto(R"(
    scalars {
      bool_field: true
      string_field: "bar"
    }
  )");

  EXPECT_THAT(result, EqualsProto(want));
}

TEST(ProtoyamlTest, RepeatedMessage) {
  YAML::Node node = YAML::Load(R"(---
scalars:
  - int_field: 123
  - bool_field: true
    string_field: bar
)");

  RepeatedScalars result;
  EXPECT_OK(YamlToProto(node, &result));

  RepeatedScalars want = ParseTestProto(R"(
    scalars {
      int_field: 123
    }
    scalars {
      bool_field: true
      string_field: "bar"
    }
  )");

  EXPECT_THAT(result, EqualsProto(want));
}

TEST(ProtoyamlTest, RepeatedMessageReplacesDefault) {
  YAML::Node node = YAML::Load(R"(---
scalars:
  - int_field: 123
)");

  RepeatedScalars result = ParseTestProto(R"(
scalars {
  bool_field: false
})");

  EXPECT_OK(YamlToProto(node, &result));

  RepeatedScalars want = ParseTestProto(R"(
    scalars {
      int_field: 123
    })");

  EXPECT_THAT(result, EqualsProto(want));
}

}  // namespace
}  // namespace kmsp11
