/*
 * Copyright 2021 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef KMSP11_UTIL_STATUS_UTILS_H_
#define KMSP11_UTIL_STATUS_UTILS_H_

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "grpcpp/support/status.h"
#include "kmsp11/cryptoki.h"

namespace cloud_kms::kmsp11 {

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

}  // namespace cloud_kms::kmsp11

#endif  // KMSP11_UTIL_STATUS_UTILS_H_
