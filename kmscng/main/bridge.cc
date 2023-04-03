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

#include <string_view>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_format.h"
#include "common/status_macros.h"
#include "kmscng/provider.h"
#include "kmscng/util/errors.h"
#include "kmscng/util/logging.h"
#include "kmscng/util/status_utils.h"

namespace cloud_kms::kmscng {

// https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptopenstorageprovider
absl::Status OpenProvider(__out NCRYPT_PROV_HANDLE* phProvider,
                          __in LPCWSTR pszProviderName, __in DWORD dwFlags) {
  if (phProvider == nullptr) {
    return NewError(absl::StatusCode::kInvalidArgument,
                    "the provider handle cannot be null", NTE_INVALID_PARAMETER,
                    SOURCE_LOCATION);
  }
  // Check that the user is actually trying to open our provider, and not a
  // default / different provider.
  if (!pszProviderName || std::wstring_view(pszProviderName) != kProviderName) {
    return NewError(absl::StatusCode::kInvalidArgument,
                    "unexpected provider name", NTE_INVALID_PARAMETER,
                    SOURCE_LOCATION);
  }
  if (dwFlags != 0 && dwFlags != NCRYPT_SILENT_FLAG) {
    return NewError(absl::StatusCode::kInvalidArgument,
                    "unsupported flag specified", NTE_BAD_FLAGS,
                    SOURCE_LOCATION);
  }

  *phProvider = reinterpret_cast<NCRYPT_PROV_HANDLE>(new Provider());
  return absl::OkStatus();
}

// This function is called by NCryptFreeObject:
// https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptfreeobject
absl::Status FreeProvider(__in NCRYPT_PROV_HANDLE hProvider) {
  ASSIGN_OR_RETURN(Provider * prov, ValidateProviderHandle(hProvider));
  delete prov;
  return absl::OkStatus();
}

// This function is called by NCryptGetProperty:
// https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptgetproperty
absl::Status GetProviderProperty(__in NCRYPT_PROV_HANDLE hProvider,
                                 __in LPCWSTR pszProperty,
                                 __out_bcount_part_opt(cbOutput, *pcbResult)
                                     PBYTE pbOutput,
                                 __in DWORD cbOutput, __out DWORD* pcbResult,
                                 __in DWORD dwFlags) {
  ASSIGN_OR_RETURN(Provider * prov, ValidateProviderHandle(hProvider));
  if (!pszProperty) {
    return NewError(absl::StatusCode::kInvalidArgument,
                    "pszProperty cannot be null", NTE_INVALID_PARAMETER,
                    SOURCE_LOCATION);
  }
  if (!pcbResult) {
    return NewError(absl::StatusCode::kInvalidArgument,
                    "pcbResult cannot be null", NTE_INVALID_PARAMETER,
                    SOURCE_LOCATION);
  }
  if (dwFlags != 0 && dwFlags != NCRYPT_SILENT_FLAG) {
    return NewError(absl::StatusCode::kInvalidArgument,
                    "unsupported flag specified", NTE_BAD_FLAGS,
                    SOURCE_LOCATION);
  }

  ASSIGN_OR_RETURN(std::string_view property_value,
                   prov->GetProperty(pszProperty));
  *pcbResult = property_value.size();

  // Return size required to hold the property value if output buffer is null.
  if (!pbOutput) {
    return absl::OkStatus();
  }

  // Check provided buffer size to ensure the property value fits.
  if (cbOutput < property_value.size()) {
    return NewError(absl::StatusCode::kOutOfRange,
                    absl::StrFormat("cbOutput size=%u not large enough to fit "
                                    "property value of size %u",
                                    cbOutput, property_value.size()),
                    NTE_BUFFER_TOO_SMALL, SOURCE_LOCATION);
  }

  property_value.copy(reinterpret_cast<char*>(pbOutput), property_value.size());
  return absl::OkStatus();
}

// This function is called by NCryptSetProperty:
// https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptsetproperty
absl::Status SetProviderProperty(__in NCRYPT_PROV_HANDLE hProvider,
                                 __in LPCWSTR pszProperty,
                                 __in_bcount(cbInput) PBYTE pbInput,
                                 __in DWORD cbInput, __in DWORD dwFlags) {
  ASSIGN_OR_RETURN(Provider * prov, ValidateProviderHandle(hProvider));
  if (!pszProperty) {
    return NewError(absl::StatusCode::kInvalidArgument,
                    "pszProperty cannot be null", NTE_INVALID_PARAMETER,
                    SOURCE_LOCATION);
  }
  if (!pbInput) {
    return NewError(absl::StatusCode::kInvalidArgument,
                    "pbInput cannot be null", NTE_INVALID_PARAMETER,
                    SOURCE_LOCATION);
  }
  if (dwFlags != 0 && dwFlags != NCRYPT_SILENT_FLAG) {
    return NewError(absl::StatusCode::kInvalidArgument,
                    "unsupported flag specified", NTE_BAD_FLAGS,
                    SOURCE_LOCATION);
  }

  return prov->SetProperty(
      pszProperty, std::string(reinterpret_cast<char*>(pbInput), cbInput));
}

}  // namespace cloud_kms::kmscng
