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

#include "kmscng/main/bridge.h"

#include "gmock/gmock.h"
#include "kmscng/cng_headers.h"
#include "kmscng/test/matchers.h"

namespace cloud_kms::kmscng {
namespace {

TEST(BridgeTest, OpenProviderSuccess) {
  NCRYPT_PROV_HANDLE hProvider;
  absl::Status status = OpenProvider(&hProvider, L"libkmscng.dll", 0);
  EXPECT_THAT(status, StatusSsIs(ERROR_SUCCESS));
}

TEST(BridgeTest, OpenProviderInvalidHandle) {
  NCRYPT_PROV_HANDLE* hProvider = nullptr;
  absl::Status status = OpenProvider(hProvider, L"libkmscng.dll", 0);
  EXPECT_THAT(status, StatusSsIs(NTE_INVALID_PARAMETER));
}

TEST(BridgeTest, FreeProviderSuccess) {
  NCRYPT_PROV_HANDLE hProvider;
  absl::Status status = OpenProvider(&hProvider, L"libkmscng.dll", 0);
  EXPECT_THAT(status, StatusSsIs(ERROR_SUCCESS));

  status = FreeProvider(hProvider);
  EXPECT_THAT(status, StatusSsIs(ERROR_SUCCESS));
}

}  // namespace
}  // namespace cloud_kms::kmscng
