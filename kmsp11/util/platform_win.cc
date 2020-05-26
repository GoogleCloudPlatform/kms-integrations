#include "kmsp11/util/errors.h"
#include "kmsp11/util/platform.h"

void SetEnvVariable(const std::string& name, const std::string& value) {
  _putenv_s(name.c_str(), value.c_str());
}

void ClearEnvVariable(const std::string& name) { _putenv_s(name.c_str(), ""); }

absl::Status EnsureWriteProtected(const char* filename) {
  return absl::OkStatus();
}

absl::Status SetMode(const char* filename, int mode) {
  return NewError(absl::StatusCode::kUnimplemented,
                  "SetMode is not implemented on Windows", CKR_GENERAL_ERROR,
                  SOURCE_LOCATION);
}