// Copyright 2021 Google LLC
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

#include "kmsp11/mechanism.h"

#include "absl/container/flat_hash_map.h"
#include "kmsp11/util/errors.h"

namespace kmsp11 {
namespace {

constexpr CK_FLAGS kEcFlags =
    CKF_EC_F_P | CKF_EC_NAMEDCURVE | CKF_EC_UNCOMPRESS;

static const auto* const kMechanisms =
    new absl::flat_hash_map<CK_MECHANISM_TYPE, const CK_MECHANISM_INFO>({
        {
            CKM_ECDSA,
            {
                256,                              // ulMinKeySize
                384,                              // ulMaxKeySize
                CKF_SIGN | CKF_VERIFY | kEcFlags  // flags
            },

        },
        {
            CKM_EC_KEY_PAIR_GEN,
            {
                256,                                       // ulMinKeySize
                384,                                       // ulMaxKeySize
                CKF_HW | CKF_GENERATE_KEY_PAIR | kEcFlags  // flags
            },
        },
        {
            CKM_RSA_PKCS,
            {
                2048,                  // ulMinKeySize
                4096,                  // ulMaxKeySize
                CKF_SIGN | CKF_VERIFY  // flags
            },

        },
        {
            CKM_RSA_PKCS_OAEP,
            {
                2048,                      // ulMinKeySize
                4096,                      // ulMaxKeySize
                CKF_DECRYPT | CKF_ENCRYPT  // flags
            },
        },
        {
            CKM_RSA_PKCS_PSS,
            {
                2048,                  // ulMinKeySize
                4096,                  // ulMaxKeySize
                CKF_SIGN | CKF_VERIFY  // flags
            },
        },
        {
            CKM_RSA_PKCS_KEY_PAIR_GEN,
            {
                2048,                           // ulMinKeySize
                4096,                           // ulMaxKeySize
                CKF_HW | CKF_GENERATE_KEY_PAIR  // flags
            },
        },
    });

}  // namespace

absl::Span<const CK_MECHANISM_TYPE> Mechanisms() {
  static const std::vector<CK_MECHANISM_TYPE>* const kMechanismTypes = [] {
    auto* types = new std::vector<CK_MECHANISM_TYPE>();
    types->reserve(kMechanisms->size());
    for (const auto& [mechanism_type, mechanism] : *kMechanisms) {
      types->push_back(mechanism_type);
    }
    std::sort(types->begin(), types->end());
    return types;
  }();
  return *kMechanismTypes;
}

absl::StatusOr<CK_MECHANISM_INFO> MechanismInfo(CK_MECHANISM_TYPE type) {
  const auto& entry = kMechanisms->find(type);
  if (entry == kMechanisms->end()) {
    return NewError(absl::StatusCode::kNotFound,
                    absl::StrFormat("mechanism %#x not found", type),
                    CKR_MECHANISM_INVALID, SOURCE_LOCATION);
  }
  return entry->second;
}

}  // namespace kmsp11
