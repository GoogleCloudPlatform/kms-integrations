#ifndef KMSP11_UTIL_ERRORS_H_
#define KMSP11_UTIL_ERRORS_H_

#include "absl/status/status.h"
#include "absl/strings/str_format.h"
#include "kmsp11/cryptoki.h"
#include "kmsp11/util/source_location.h"
#include "kmsp11/util/status_utils.h"

namespace kmsp11 {

// Creates a new error status with the provided parameters.
// `code` and `ck_rv` must not be OK; these requirements are CHECKed.
ABSL_MUST_USE_RESULT absl::Status NewError(
    absl::StatusCode code, absl::string_view msg, CK_RV ck_rv,
    const SourceLocation& source_location);

// Creates a new error with status code unimplemented and return value of
// CKR_FUNCTION_NOT_SUPPORTED.
inline ABSL_MUST_USE_RESULT absl::Status UnsupportedError(
    SourceLocation source_location) {
  return NewError(absl::StatusCode::kUnimplemented,
                  "the function is not supported", CKR_FUNCTION_NOT_SUPPORTED,
                  source_location);
}

}  // namespace kmsp11

#endif  // KMSP11_UTIL_ERRORS_H_
