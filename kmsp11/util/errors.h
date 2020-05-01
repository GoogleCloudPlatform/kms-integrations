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

// Creates a new Internal error with a return value of
// CKR_GENERAL_ERROR.
ABSL_MUST_USE_RESULT inline absl::Status NewInternalError(
    absl::string_view msg, const SourceLocation& source_location) {
  return NewError(absl::StatusCode::kInternal, msg, CKR_GENERAL_ERROR,
                  SOURCE_LOCATION);
}

// Creates a new InvalidArgument error with the provided CK_RV.
ABSL_MUST_USE_RESULT inline absl::Status NewInvalidArgumentError(
    absl::string_view msg, CK_RV ck_rv, const SourceLocation& source_location) {
  return NewError(absl::StatusCode::kInvalidArgument, msg, ck_rv,
                  source_location);
}

// Creates a new InvalidArgument error with rv = CKR_ARGUMENTS_BAD.
ABSL_MUST_USE_RESULT inline absl::Status NullArgumentError(
    absl::string_view arg_name, const SourceLocation& source_location) {
  return NewInvalidArgumentError(
      absl::StrFormat("argument %s was unexpectedly null", arg_name),
      CKR_ARGUMENTS_BAD, source_location);
}

// Creates a new FailedPrecondition error with a return value of
// CKR_CRYPTOKI_NOT_INITIALIZED.
ABSL_MUST_USE_RESULT inline absl::Status NotInitializedError(
    const SourceLocation& source_location) {
  return NewError(absl::StatusCode::kFailedPrecondition,
                  "the library is not initialized",
                  CKR_CRYPTOKI_NOT_INITIALIZED, SOURCE_LOCATION);
}

// Creates a new error with status code unimplemented and return value of
// CKR_FUNCTION_NOT_SUPPORTED.
inline ABSL_MUST_USE_RESULT absl::Status UnsupportedError(
    const SourceLocation& source_location) {
  return NewError(absl::StatusCode::kUnimplemented,
                  "the function is not supported", CKR_FUNCTION_NOT_SUPPORTED,
                  source_location);
}

}  // namespace kmsp11

#endif  // KMSP11_UTIL_ERRORS_H_
