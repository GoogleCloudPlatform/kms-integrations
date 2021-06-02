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

#ifndef KMSP11_MECHANISM_H_
#define KMSP11_MECHANISM_H_

#include "absl/status/statusor.h"
#include "absl/types/span.h"
#include "kmsp11/cryptoki.h"

namespace kmsp11 {

// Returns a sorted list of the mechanism types supported in this library.
absl::Span<const CK_MECHANISM_TYPE> Mechanisms();

// Returns details about the provided mechanism type.
absl::StatusOr<CK_MECHANISM_INFO> MechanismInfo(CK_MECHANISM_TYPE type);

}  // namespace kmsp11

#endif  // KMSP11_MECHANISM_H_
