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

#ifndef KMSCNG_OBJECT_H_
#define KMSCNG_OBJECT_H_

#include "absl/container/flat_hash_map.h"
#include "absl/status/statusor.h"
#include "common/kms_client.h"
#include "kmscng/cng_headers.h"

namespace cloud_kms::kmscng {

class Object {
 public:
  static absl::StatusOr<Object*> Object::New(NCRYPT_PROV_HANDLE prov_handle,
                                             std::string key_name);

  absl::StatusOr<std::string_view> GetProperty(std::wstring_view name);

 private:
  Object::Object(std::string kms_key_name, std::unique_ptr<KmsClient> client,
                 absl::flat_hash_map<std::wstring, std::string> info);

  const std::string kms_key_name_;
  std::unique_ptr<KmsClient> kms_client_;
  kms_v1::CryptoKeyVersion::CryptoKeyVersionAlgorithm algorithm;
  const absl::flat_hash_map<std::wstring, std::string> key_info_;
};

// Validates the NCRYPT_PROV_HANDLE and NCRYPT_KEY_HANDLE combination and
// returns a pointer to the Object if the handles are valid, an error otherwise.
absl::StatusOr<Object*> ValidateKeyHandle(NCRYPT_PROV_HANDLE prov_handle,
                                          NCRYPT_KEY_HANDLE key_handle);

}  // namespace cloud_kms::kmscng

#endif KMSCNG_OBJECT_H_
