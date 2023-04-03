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

#include <cwchar>

#include "absl/container/flat_hash_set.h"
#include "kmscng/cng_headers.h"
#include "kmscng/util/errors.h"
#include "kmscng/version.h"

namespace cloud_kms::kmscng {
namespace {

absl::flat_hash_set<std::wstring> mutable_properties = {
    {kEndpointAddressProperty.data()},
    {kChannelCredentialsProperty.data()},
};

std::string ToString(uint32_t value) {
  uint32_t value_copy = value;
  return std::string(reinterpret_cast<char*>(&value_copy), sizeof(uint32_t));
}

absl::flat_hash_map<std::wstring, std::string> BuildInfo() {
  return {
      {NCRYPT_IMPL_TYPE_PROPERTY, ToString(NCRYPT_IMPL_HARDWARE_FLAG)},
      {NCRYPT_VERSION_PROPERTY, ToString(kLibraryVersionHex)},
      {std::wstring(kEndpointAddressProperty), "cloudkms.googleapis.com:443"},
      {std::wstring(kChannelCredentialsProperty), "default"},
  };
}

}  // namespace

Provider::Provider() : provider_info_(BuildInfo()) {}

absl::StatusOr<std::string_view> Provider::GetProperty(std::wstring_view name) {
  auto it = provider_info_.find(name);
  if (it == provider_info_.end()) {
    return NewError(absl::StatusCode::kNotFound,
                    "unsupported property specified", NTE_NOT_SUPPORTED,
                    SOURCE_LOCATION);
  }
  return it->second;
}

absl::Status Provider::SetProperty(std::wstring_view name,
                                   std::string_view value) {
  auto it = provider_info_.find(name);
  if (it == provider_info_.end()) {
    return NewError(absl::StatusCode::kNotFound,
                    "unsupported property specified", NTE_NOT_SUPPORTED,
                    SOURCE_LOCATION);
  }
  if (!mutable_properties.contains(name)) {
    return NewError(absl::StatusCode::kInvalidArgument,
                    "the specified property cannot be updated",
                    NTE_INVALID_PARAMETER, SOURCE_LOCATION);
  }

  it->second = value;
  return absl::OkStatus();
}

}  // namespace cloud_kms::kmscng
