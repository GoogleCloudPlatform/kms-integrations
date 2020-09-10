#ifndef KMSP11_CONFIG_CONFIG_H_
#define KMSP11_CONFIG_CONFIG_H_

#include "absl/status/statusor.h"
#include "kmsp11/config/config.pb.h"

namespace kmsp11 {

const char* const kConfigEnvVariable = "KMS_PKCS11_CONFIG";

absl::StatusOr<LibraryConfig> LoadConfigFromEnvironment();
absl::StatusOr<LibraryConfig> LoadConfigFromFile(
    const std::string& config_file_path);

}  // namespace kmsp11

#endif  // KMSP11_CONFIG_CONFIG_H_
