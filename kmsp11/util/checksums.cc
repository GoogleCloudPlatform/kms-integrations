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

#include <crc32c/crc32c.h>

#include <string>

#include "absl/types/span.h"

namespace kmsp11 {

uint32_t ComputeCRC32C(const uint8_t* data, size_t length) {
  return crc32c::Crc32c(data, length);
}

uint32_t ComputeCRC32C(std::string_view data) {
  return ComputeCRC32C(reinterpret_cast<const uint8_t*>(data.data()),
                       data.size());
}

bool CRC32CMatches(const uint8_t* data, size_t length, uint32_t crc32c) {
  return crc32c == ComputeCRC32C(data, length);
}

bool CRC32CMatches(std::string_view data, uint32_t crc32c) {
  return CRC32CMatches(reinterpret_cast<const uint8_t*>(data.data()),
                       data.size(), crc32c);
}

}  // namespace kmsp11
