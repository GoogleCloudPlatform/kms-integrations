#ifndef KMSP11_UTIL_STATUS_UTILS_H_
#define KMSP11_UTIL_STATUS_UTILS_H_

#include "absl/status/status.h"
#include "kmsp11/util/status_or.h"

namespace kmsp11 {

// These functions permit us to call ToStatus(x) on varying types of statuses.
// In the future, we'll need to deal with gRPC and cloud-cpp statuses as well.

inline const absl::Status& ToStatus(const absl::Status& status) {
  return status;
}

template <typename T>
inline const absl::Status& ToStatus(const kmsp11::StatusOr<T>& status_or) {
  return status_or.status();
}

}  // namespace kmsp11

#endif  // KMSP11_UTIL_STATUS_UTILS_H_
