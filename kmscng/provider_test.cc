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

#include "kmscng/provider.h"

#include "common/test/test_status_macros.h"
#include "gmock/gmock.h"
#include "kmscng/cng_headers.h"
#include "kmscng/test/matchers.h"
#include "kmscng/version.h"

namespace cloud_kms::kmscng {
namespace {

std::string ToString(uint32_t value) {
  uint32_t value_copy = value;
  return std::string(reinterpret_cast<char*>(&value), sizeof(value));
}

TEST(ProviderTest, GetProviderPropertyUnsupportedProperty) {
  Provider provider;

  EXPECT_THAT(provider.GetProperty(NCRYPT_UI_POLICY_PROPERTY),
              StatusSsIs(NTE_NOT_SUPPORTED));
}

TEST(ProviderTest, GetProviderPropertyImplTypeSuccess) {
  Provider provider;

  EXPECT_THAT(provider.GetProperty(NCRYPT_IMPL_TYPE_PROPERTY),
              IsOkAndHolds(ToString(NCRYPT_IMPL_HARDWARE_FLAG)));
}

TEST(ProviderTest, GetProviderPropertyLibraryVersionSuccess) {
  Provider provider;

  EXPECT_THAT(provider.GetProperty(NCRYPT_VERSION_PROPERTY),
              IsOkAndHolds(ToString(kLibraryVersionHex)));
}

TEST(ProviderTest, GetProviderPropertyEndpointAddressSuccess) {
  Provider provider;

  EXPECT_THAT(provider.GetProperty(kEndpointAddressProperty),
              IsOkAndHolds("cloudkms.googleapis.com:443"));
}

TEST(ProviderTest, GetProviderPropertyChannelCredentialsSuccess) {
  Provider provider;

  EXPECT_THAT(provider.GetProperty(kChannelCredentialsProperty),
              IsOkAndHolds("default"));
}

TEST(ProviderTest, SetProviderPropertyUnsupportedProperty) {
  Provider provider;

  EXPECT_THAT(provider.SetProperty(NCRYPT_UI_POLICY_PROPERTY, ""),
              StatusSsIs(NTE_NOT_SUPPORTED));
}

TEST(ProviderTest, SetProviderPropertyImmutableProperty) {
  Provider provider;

  EXPECT_THAT(provider.SetProperty(NCRYPT_IMPL_TYPE_PROPERTY, ""),
              StatusSsIs(NTE_INVALID_PARAMETER));
}

TEST(ProviderTest, SetProviderPropertySuccess) {
  Provider provider;

  std::string input = "insecure";
  EXPECT_OK(provider.SetProperty(kChannelCredentialsProperty, input));
  EXPECT_THAT(provider.GetProperty(kChannelCredentialsProperty),
              IsOkAndHolds("insecure"));
}

}  // namespace
}  // namespace cloud_kms::kmscng
