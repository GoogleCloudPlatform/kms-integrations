#include "kmsp11/config/config.h"

#include <cstdlib>

#include "kmsp11/config/protoyaml.h"
#include "kmsp11/util/errors.h"
#include "kmsp11/util/status_macros.h"
#include "yaml-cpp/yaml.h"

namespace kmsp11 {

StatusOr<LibraryConfig> LoadConfigFromEnvironment() {
  char* env_value = std::getenv(kConfigEnvVariable);
  if (!env_value) {
    return FailedPreconditionError(
        absl::StrFormat(
            "cannot load configuration: environment variable %s is not set",
            kConfigEnvVariable),
        CKR_GENERAL_ERROR, SOURCE_LOCATION);
  }
  return LoadConfigFromFile(env_value);
}

// Exceptions are disallowed by our style guide. Wrap YAML::LoadFile (which may
// throw) in a noexcept function, and convert thrown exceptions to a reasonable
// absl::Status.
StatusOr<YAML::Node> ParseYamlFile(const std::string& file_path) noexcept {
  try {
    return YAML::LoadFile(file_path);
  } catch (const YAML::Exception& e) {
    return NewInvalidArgumentError(
        absl::StrFormat("error parsing file at %s: %s", file_path, e.what()),
        CKR_GENERAL_ERROR, SOURCE_LOCATION);
  }
}

StatusOr<LibraryConfig> LoadConfigFromFile(const std::string& config_path) {
  ASSIGN_OR_RETURN(YAML::Node node, ParseYamlFile(config_path));
  LibraryConfig config;
  RETURN_IF_ERROR(YamlToProto(node, &config));
  return config;
}

}  // namespace kmsp11
