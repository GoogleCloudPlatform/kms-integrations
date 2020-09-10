#ifndef KMSP11_UTIL_STATUS_UTILS_H_
#define KMSP11_UTIL_STATUS_UTILS_H_

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "google/cloud/status_or.h"
#include "grpcpp/support/status.h"
#include "kmsp11/cryptoki.h"

namespace kmsp11 {

// A catch-all default Cryptoki error value to return in the event that no
// specific error is provided.
const CK_RV kDefaultErrorCkRv = CKR_FUNCTION_FAILED;

// Set an error CK_RV that should be provided to the caller. This may not be set
// for an `ok` status, and CKR_OK may not be set as the return value. These
// requirements are CHECKed.
void SetErrorRv(absl::Status& status, CK_RV rv);

// Get a CK_RV suitable for returning to a caller. For an `ok` status, this is
// always CKR_OK. For a non-OK status, this is the value that was set using
// SetCkRv, or if no value was set, `kDefaultErrorCkRv`.
CK_RV GetCkRv(const absl::Status& status);

// These functions permit us to call ToStatus(x) on varying types of statuses.

inline const absl::Status& ToStatus(const absl::Status& status) {
  return status;
}

template <typename T>
inline const absl::Status& ToStatus(const absl::StatusOr<T>& status_or) {
  return status_or.status();
}

inline absl::Status ToStatus(const grpc::Status& status) {
  return absl::Status(absl::StatusCode(status.error_code()),
                      status.error_message());
}

inline absl::Status ToStatus(const google::cloud::Status& status) {
  return absl::Status(absl::StatusCode(status.code()), status.message());
}

template <typename T>
inline absl::Status ToStatus(const google::cloud::StatusOr<T>& status_or) {
  return ToStatus(status_or.status());
}

}  // namespace kmsp11

#endif  // KMSP11_UTIL_STATUS_UTILS_H_
