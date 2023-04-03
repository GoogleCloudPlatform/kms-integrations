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

#include <cwchar>

#include "absl/strings/str_format.h"
#include "common/test/test_status_macros.h"
#include "gmock/gmock.h"
#include "kmscng/cng_headers.h"
#include "kmscng/test/register_provider.h"

#define ASSERT_SUCCESS(arg) ASSERT_EQ(arg, 0)
#define EXPECT_SUCCESS(arg) EXPECT_EQ(arg, 0)

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)
#endif

namespace cloud_kms::kmscng {
namespace {

class RegisteredProviderTest : public testing::Test {
 protected:
  static void SetUpTestSuite() { ASSERT_OK(RegisterTestProvider()); }

  static void TearDownTestSuite() { ASSERT_OK(UnregisterTestProvider()); }
};

TEST_F(RegisteredProviderTest, OpenCloseProviderSuccess) {
  NCRYPT_PROV_HANDLE provider_handle;
  NTSTATUS status =
      NCryptOpenStorageProvider(&provider_handle, kProviderName.data(), 0);
  EXPECT_SUCCESS(status);
  if (!NT_SUCCESS(status)) {
    std::cerr << absl::StrFormat(
        "NCryptOpenStorageProvider failed with error code 0x%08x\n", status);
  }
  EXPECT_NE(provider_handle, 0);

  EXPECT_SUCCESS(NCryptFreeObject(provider_handle));
}

TEST_F(RegisteredProviderTest, GetProviderPropertySuccess) {
  NCRYPT_PROV_HANDLE provider_handle;
  EXPECT_SUCCESS(
      NCryptOpenStorageProvider(&provider_handle, kProviderName.data(), 0));

  DWORD output = 0;
  DWORD output_size = 0;
  NTSTATUS status = NCryptGetProperty(
      provider_handle, NCRYPT_IMPL_TYPE_PROPERTY,
      reinterpret_cast<uint8_t*>(&output), sizeof(output), &output_size, 0);
  EXPECT_SUCCESS(status);
  if (!NT_SUCCESS(status)) {
    std::cerr << absl::StrFormat(
        "NCryptGetProperty failed with error code 0x%08x\n", status);
  }
  EXPECT_EQ(output_size, sizeof(output));
  EXPECT_EQ(output, NCRYPT_IMPL_HARDWARE_FLAG);

  EXPECT_SUCCESS(NCryptFreeObject(provider_handle));
}

TEST_F(RegisteredProviderTest, SetProviderPropertySuccess) {
  NCRYPT_PROV_HANDLE provider_handle;
  EXPECT_SUCCESS(
      NCryptOpenStorageProvider(&provider_handle, kProviderName.data(), 0));

  std::string input = "insecure";
  NTSTATUS status = NCryptSetProperty(
      provider_handle, const_cast<wchar_t*>(kChannelCredentialsProperty.data()),
      reinterpret_cast<uint8_t*>(input.data()), input.size(), 0);
  EXPECT_SUCCESS(status);
  if (!NT_SUCCESS(status)) {
    std::cerr << absl::StrFormat(
        "NCryptSetProperty failed with error code 0x%08x\n", status);
  }

  std::string output("0", input.size());
  DWORD output_size = 0;
  EXPECT_SUCCESS(NCryptGetProperty(
      provider_handle, const_cast<wchar_t*>(kChannelCredentialsProperty.data()),
      reinterpret_cast<uint8_t*>(output.data()), input.size(), &output_size,
      0));
  EXPECT_EQ(output_size, output.size());
  EXPECT_EQ(output, "insecure");

  EXPECT_SUCCESS(NCryptFreeObject(provider_handle));
}

}  // namespace
}  // namespace cloud_kms::kmscng
