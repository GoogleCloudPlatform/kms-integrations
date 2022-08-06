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

#include "absl/types/span.h"
#include "gmock/gmock.h"

namespace kmsp11 {
namespace {

std::string kInputString = "hardcoded data";
absl::Span<const uint8_t> kInputData(
    reinterpret_cast<const uint8_t*>(kInputString.data()), kInputString.size());
constexpr uint32_t kExpectedCrc32c = 4206952968;

TEST(ChecksumsTest, ChecksumMatchesExpected) {
  EXPECT_EQ(ComputeCRC32C(kInputData.data(), kInputData.size()),
            kExpectedCrc32c);
}

TEST(ChecksumsTest, ComputeVerifySuccess) {
  uint32_t checksum = ComputeCRC32C(kInputData.data(), kInputData.size());

  EXPECT_TRUE(CRC32CMatches(kInputData.data(), kInputData.size(), checksum));
}

TEST(ChecksumsTest, ChecksumIsConsistent) {
  uint32_t checksum = ComputeCRC32C(kInputData.data(), kInputData.size());
  uint32_t consistent_checksum =
      ComputeCRC32C(kInputData.data(), kInputData.size());

  EXPECT_EQ(checksum, consistent_checksum);
}

// ComputeCRC32C("") should return 0.
TEST(ChecksumsTest, EmptyDataYieldsZeroChecksum) {
  const uint8_t data = {};
  EXPECT_EQ(ComputeCRC32C(&data, 0), 0);
}

}  // namespace
}  // namespace kmsp11
