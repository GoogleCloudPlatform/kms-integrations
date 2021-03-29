
#include "kmsp11/util/backoff.h"

#include "glog/logging.h"

namespace kmsp11 {

absl::Duration ComputeBackoff(absl::Duration min_delay,
                              absl::Duration max_delay, int previous_retries) {
  if (min_delay < absl::Nanoseconds(1)) {
    LOG_FIRST_N(WARNING, 100) << "ComputeBackoff increasing min_delay from "
                              << min_delay << " to 1ns.";
    min_delay = absl::Nanoseconds(1);
  }
  if (max_delay < min_delay) {
    LOG_FIRST_N(WARNING, 100)
        << "ComputeBackoff increasing max_delay of " << max_delay
        << " to match min_delay of " << min_delay << ".";
    max_delay = min_delay;
  }
  if (previous_retries < 0) {
    LOG_FIRST_N(WARNING, 100)
        << "ComputeBackoff increasing previous_retries from "
        << previous_retries << " to 0.";
    previous_retries = 0;
  }

  constexpr double kBackoffMultiplier = 1.3;
  absl::Duration uncapped_delay =
      min_delay * std::pow(kBackoffMultiplier, previous_retries);
  absl::Duration delay = std::min(uncapped_delay, max_delay);

  // Ensure that floating point errors don't cause us to violate our contract.
  delay = std::max(delay, min_delay);
  return delay;
}

}  // namespace kmsp11