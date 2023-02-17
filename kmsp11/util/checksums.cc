// Copyright 2022 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "kmsp11/util/checksums.h"

#include <string>

#include "absl/crc/crc32c.h"
#include "absl/types/span.h"

namespace kmsp11 {

uint32_t ComputeCRC32C(std::string_view data) {
  return static_cast<uint32_t>(absl::ComputeCrc32c(data));
}

bool CRC32CMatches(std::string_view data, uint32_t crc32c) {
  return crc32c == ComputeCRC32C(data);
}

}  // namespace kmsp11
