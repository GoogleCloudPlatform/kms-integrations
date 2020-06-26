#include "kmsp11/util/errors.h"
#include "kmsp11/util/platform.h"

namespace kmsp11 {

void SetEnvVariable(const char* name, const char* value) {
  _putenv_s(name, value);
}

void ClearEnvVariable(const char* name) { _putenv_s(name, ""); }

absl::Status EnsureWriteProtected(const char* filename) {
  return absl::OkStatus();
}

absl::Status SetMode(const char* filename, int mode) {
  return NewError(absl::StatusCode::kUnimplemented,
                  "SetMode is not implemented on Windows", CKR_GENERAL_ERROR,
                  SOURCE_LOCATION);
}

}  // namespace kmsp11
