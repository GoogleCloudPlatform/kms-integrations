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

#ifndef KMSP11_UTIL_BACKOFF_H_
#define KMSP11_UTIL_BACKOFF_H_

#include "absl/time/time.h"

namespace cloud_kms::kmsp11 {

absl::Duration ComputeBackoff(absl::Duration min_delay,
                              absl::Duration max_delay, int previous_tries);

}  // namespace cloud_kms::kmsp11

#endif  // KMSP11_UTIL_BACKOFF_H_
