#include "kmsp11/config/config.h"

#include <fstream>

#include "gmock/gmock.h"
#include "kmsp11/test/matchers.h"
#include "kmsp11/test/proto_parser.h"
#include "kmsp11/test/test_status_macros.h"
#include "kmsp11/util/cleanup.h"
#include "kmsp11/util/platform.h"

namespace kmsp11 {
namespace {

using ::testing::HasSubstr;

class ConfigFileTest : public testing::Test {
 protected:
  ConfigFileTest() : config_path_(std::tmpnam(nullptr)){};
  virtual ~ConfigFileTest() { std::remove(config_path_.c_str()); }

  std::string config_path_;
};

TEST_F(ConfigFileTest, SingleToken) {
  std::ofstream(config_path_) << R"(---
tokens:
  - key_ring: projects/foo/locations/global/keyRings/bar
)";

  ASSERT_OK_AND_ASSIGN(LibraryConfig config, LoadConfigFromFile(config_path_));
  EXPECT_THAT(config, EqualsProto<LibraryConfig>(ParseTestProto(R"(
      tokens {
        key_ring: "projects/foo/locations/global/keyRings/bar"
      })")));
}

TEST_F(ConfigFileTest, MultipleTokens) {
  std::ofstream(config_path_) << R"(---
tokens:
  - key_ring: projects/foo/locations/global/keyRings/bar
  - key_ring: projects/foo/locations/global/keyRings/baz
  - key_ring: projects/foo/locations/global/keyRings/qux
)";

  ASSERT_OK_AND_ASSIGN(LibraryConfig config, LoadConfigFromFile(config_path_));
  EXPECT_THAT(config, EqualsProto<LibraryConfig>(ParseTestProto(R"(
      tokens {
        key_ring: "projects/foo/locations/global/keyRings/bar"
      }
      tokens {
        key_ring: "projects/foo/locations/global/keyRings/baz"
      }
      tokens {
        key_ring: "projects/foo/locations/global/keyRings/qux"
      })")));
}

TEST_F(ConfigFileTest, TokenWithLabel) {
  std::ofstream(config_path_) << R"(---
tokens:
  - key_ring: projects/foo/locations/global/keyRings/bar
    label: bar
)";

  ASSERT_OK_AND_ASSIGN(LibraryConfig config, LoadConfigFromFile(config_path_));
  EXPECT_THAT(config, EqualsProto<LibraryConfig>(ParseTestProto(R"(
      tokens {
        key_ring: "projects/foo/locations/global/keyRings/bar"
        label: "bar"
      })")));
}

TEST_F(ConfigFileTest, InvalidArgumentOnMalformedConfig) {
  std::ofstream(config_path_) << "this is not yaml";
  EXPECT_THAT(LoadConfigFromFile(config_path_),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_F(ConfigFileTest, LocationProvidedOnMalformedConfig) {
  std::ofstream(config_path_) << R"(---
tokens:
  - key_ring: foo/bar/baz
  - fake_field: oops
)";

  StatusOr<LibraryConfig> result = LoadConfigFromFile(config_path_);
  EXPECT_THAT(result.status().message(), HasSubstr("line 3, column 4"));
}

TEST_F(ConfigFileTest, InvalidArgumentOnMissingConfig) {
  EXPECT_THAT(LoadConfigFromFile(config_path_),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_F(ConfigFileTest, LoadConfigFromEnvironmentSuccess) {
  std::ofstream(config_path_) << R"(---
tokens:
  - key_ring: projects/foo/locations/global/keyRings/bar
)";
  SetEnvVariable(kConfigEnvVariable, config_path_);
  Cleanup c([]() { ClearEnvVariable(kConfigEnvVariable); });

  ASSERT_OK_AND_ASSIGN(LibraryConfig config, LoadConfigFromEnvironment());
  EXPECT_THAT(config, EqualsProto<LibraryConfig>(ParseTestProto(R"(
      tokens {
        key_ring: "projects/foo/locations/global/keyRings/bar"
      })")));
}

TEST_F(ConfigFileTest, LoadConfigFromEnvironmentMissing) {
  StatusOr<LibraryConfig> result = LoadConfigFromEnvironment();
  EXPECT_THAT(result, StatusIs(absl::StatusCode::kFailedPrecondition));
  EXPECT_THAT(result.status().message(), HasSubstr(kConfigEnvVariable));
}

TEST_F(ConfigFileTest, LoadConfigFromEnvironmentInlineFailure) {
  std::string config = R"(---
tokens:
  - key_ring: projects/foo/locations/global/keyRings/bar
)";
  SetEnvVariable(kConfigEnvVariable, config);
  Cleanup c([]() { ClearEnvVariable(kConfigEnvVariable); });

  StatusOr<LibraryConfig> result = LoadConfigFromEnvironment();
  EXPECT_THAT(result.status(), StatusIs(absl::StatusCode::kInvalidArgument));
  EXPECT_THAT(result.status().message(), HasSubstr("bad file"));
}

TEST_F(ConfigFileTest, LoadConfigFileBadPermissions) {
#ifdef _WIN32
  GTEST_SKIP() << "file permissions checks are not yet supported on windows";
#endif

  std::ofstream(config_path_) << R"(---
tokens:
  - key_ring: projects/foo/locations/global/keyRings/bar
    label: bar
)";
  EXPECT_OK(SetMode(config_path_.c_str(), 0777));

  StatusOr<LibraryConfig> result = LoadConfigFromFile(config_path_);
  EXPECT_THAT(result.status(), StatusIs(absl::StatusCode::kFailedPrecondition));
  EXPECT_THAT(result.status().message(),
              HasSubstr("excessive write permissions"));
}

}  // namespace
}  // namespace kmsp11
