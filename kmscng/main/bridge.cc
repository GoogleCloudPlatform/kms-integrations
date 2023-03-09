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

#include "absl/status/status.h"
#include "common/status_macros.h"
#include "kmscng/provider.h"
#include "kmscng/util/errors.h"
#include "kmscng/util/status_utils.h"

namespace cloud_kms::kmscng {

absl::Status OpenProvider(__out NCRYPT_PROV_HANDLE* phProvider,
                          __in LPCWSTR pszProviderName, __in DWORD dwFlags) {
  if (phProvider == nullptr) {
    return NewError(absl::StatusCode::kInvalidArgument,
                    "The provider handle cannot be null", NTE_INVALID_PARAMETER,
                    SOURCE_LOCATION);
  }

  Provider* prov = Provider::New();
  static_assert(std::numeric_limits<NCRYPT_PROV_HANDLE>::max ==
                    std::numeric_limits<ULONG_PTR>::max,
                "NCRYPT_PROV_HANDLE width mismatches pointer width.");
  *phProvider = reinterpret_cast<NCRYPT_PROV_HANDLE>(prov);
  return absl::OkStatus();
}

absl::Status FreeProvider(__in NCRYPT_PROV_HANDLE hProvider) {
  static_assert(std::numeric_limits<NCRYPT_PROV_HANDLE>::max ==
                    std::numeric_limits<ULONG_PTR>::max,
                "NCRYPT_PROV_HANDLE width mismatches pointer width.");
  Provider* prov = reinterpret_cast<Provider*>(hProvider);
  if (!prov) {
    return NewError(absl::StatusCode::kInvalidArgument,
                    "The provider handle cannot be null", NTE_INVALID_PARAMETER,
                    SOURCE_LOCATION);
  }
  delete prov;
  return absl::OkStatus();
}

}  // namespace cloud_kms::kmscng
