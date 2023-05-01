/*
 * Copyright 2023 Google LLC
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

#ifndef KMSCNG_UTIL_REGISTRATION_H_
#define KMSCNG_UTIL_REGISTRATION_H_

#include "absl/status/status.h"

namespace cloud_kms::kmscng {

// Register custom provider for use in tests.
absl::Status RegisterProvider();

// Unregister custom provider after use in tests.
absl::Status UnregisterProvider();

}  // namespace cloud_kms::kmscng

#endif  // KMSCNG_UTIL_REGISTRATION_H_
