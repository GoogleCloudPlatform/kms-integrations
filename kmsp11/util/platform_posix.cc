#include <errno.h>
#include <sys/stat.h>

#include "kmsp11/util/errors.h"
#include "kmsp11/util/platform.h"

namespace kmsp11 {

void SetEnvVariable(const char* name, const char* value) {
  setenv(name, value, 1);
}

void ClearEnvVariable(const char* name) { unsetenv(name); }

absl::Status EnsureWriteProtected(const char* filename) {
  struct stat buf;
  if (stat(filename, &buf) != 0) {
    return NewError(
        absl::StatusCode::kNotFound,
        absl::StrFormat("unable to stat file %s: error %d", filename, errno),
        CKR_GENERAL_ERROR, SOURCE_LOCATION);
  }

  if ((buf.st_mode & S_IWGRP) == S_IWGRP ||
      (buf.st_mode & S_IWOTH) == S_IWOTH) {
    return NewError(
        absl::StatusCode::kFailedPrecondition,
        absl::StrFormat("file %s has excessive write permissions", filename),
        CKR_GENERAL_ERROR, SOURCE_LOCATION);
  }

  return absl::OkStatus();
}

absl::Status SetMode(const char* filename, int mode) {
  if (chmod(filename, mode) != 0) {
    return NewError(
        absl::StatusCode::kPermissionDenied,
        absl::StrFormat("unable to change mode of file %s: error %d", filename,
                        errno),
        CKR_GENERAL_ERROR, SOURCE_LOCATION);
  }
  return absl::OkStatus();
}

}  // namespace kmsp11
