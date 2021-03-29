#ifndef KMSP11_UTIL_BACKOFF_H_
#define KMSP11_UTIL_BACKOFF_H_

#include "absl/time/time.h"

namespace kmsp11 {

absl::Duration ComputeBackoff(absl::Duration min_delay,
                              absl::Duration max_delay, int previous_tries);

}  // namespace kmsp11

#endif  // KMSP11_UTIL_BACKOFF_H_
