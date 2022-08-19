/*
 * Copyright 2022 Google LLC
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

#ifndef KMSP11_UTIL_CHECKSUMS_H_
#define KMSP11_UTIL_CHECKSUMS_H_

#include <string>

#include "absl/types/span.h"

namespace kmsp11 {

// Compute CRC32C of data. Not to be used for cryptographic integrity
// protection. Only for detection of hardware errors.
uint32_t ComputeCRC32C(const uint8_t* data, size_t length);

uint32_t ComputeCRC32C(std::string_view data);

// Computes CRC32C of data and compares to given crc32c.
bool CRC32CMatches(const uint8_t* data, size_t length, uint32_t crc32c);

bool CRC32CMatches(std::string_view data, uint32_t crc32c);

}  // namespace kmsp11

#endif  // KMSP11_UTIL_CHECKSUMS_H_
