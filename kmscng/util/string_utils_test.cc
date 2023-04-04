// Copyright 2023 Google LLC
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

#include "kmscng/util/string_utils.h"

#include "common/test/test_status_macros.h"
#include "gmock/gmock.h"

namespace cloud_kms::kmscng {
namespace {

TEST(Uint32ToBytesTest, Success) {
  uint32_t bytes = 0x44434241;
  EXPECT_EQ(Uint32ToBytes(bytes), "ABCD");
}

TEST(ProvHandleToBytesTest, Success) {
  NCRYPT_PROV_HANDLE handle = 1;
  // Use string constructor to handle \x00.
  EXPECT_EQ(ProvHandleToBytes(handle), std::string("\x1\0\0\0\0\0\0\0", 8));
}

TEST(WideStringTest, StringToWideSuccess) {
  std::string data = "1337";
  EXPECT_EQ(StringToWide(data), L"\x3133\x3337");
}

TEST(WideStringTest, WideToStringSuccess) {
  std::wstring data = L"\x3133\x3337";
  EXPECT_EQ(WideToString(data), "1337");
}

TEST(WideStringTest, StringToWideAndBackSuccess) {
  std::string data = "1337";
  EXPECT_EQ(WideToString(StringToWide(data)), "1337");
}

}  // namespace
}  // namespace cloud_kms::kmscng
