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

#include "kmscng/object.h"

#include <cwchar>

#include "common/kms_client.h"
#include "common/kms_v1.h"
#include "common/status_macros.h"
#include "kmscng/algorithm_details.h"
#include "kmscng/cng_headers.h"
#include "kmscng/provider.h"
#include "kmscng/util/errors.h"
#include "kmscng/util/status_utils.h"
#include "kmscng/util/string_utils.h"
#include "kmscng/version.h"

namespace cloud_kms::kmscng {
namespace {

absl::StatusOr<std::unique_ptr<KmsClient>> NewKmsClient(
    NCRYPT_PROV_HANDLE prov_handle) {
  ASSIGN_OR_RETURN(Provider * prov, ValidateProviderHandle(prov_handle));
  ASSIGN_OR_RETURN(std::string_view endpoint_address,
                   prov->GetProperty(kEndpointAddressProperty));
  ASSIGN_OR_RETURN(std::string_view creds_type,
                   prov->GetProperty(kChannelCredentialsProperty));
  std::shared_ptr<grpc::ChannelCredentials> creds =
      (creds_type == "insecure") ? grpc::InsecureChannelCredentials()
                                 : grpc::GoogleDefaultCredentials();
  absl::Duration rpc_timeout = absl::Seconds(30);

  return std::make_unique<KmsClient>(
      endpoint_address, creds, rpc_timeout, kLibraryVersionMajor,
      kLibraryVersionMinor, UserAgent::kCng,
      [](absl::Status& status) { SetErrorSs(status, NTE_INTERNAL_ERROR); });
}

absl::StatusOr<kms_v1::CryptoKeyVersion::CryptoKeyVersionAlgorithm>
GetKeyAlgorithm(const KmsClient& client, std::string key_name) {
  kms_v1::GetPublicKeyRequest pub_req;
  pub_req.set_name(key_name);
  ASSIGN_OR_RETURN(kms_v1::PublicKey pub_resp, client.GetPublicKey(pub_req));
  return pub_resp.algorithm();
}

absl::flat_hash_map<std::wstring, std::string> BuildInfo(
    NCRYPT_PROV_HANDLE prov_handle, std::string key_name,
    AlgorithmDetails details) {
  return {
      {NCRYPT_ALGORITHM_GROUP_PROPERTY, WideToString(details.algorithm_group)},
      {NCRYPT_ALGORITHM_PROPERTY, WideToString(details.algorithm_property)},
      {NCRYPT_KEY_USAGE_PROPERTY, Uint32ToBytes(details.key_usage)},
      {NCRYPT_NAME_PROPERTY, key_name},
      {NCRYPT_PROVIDER_HANDLE_PROPERTY,
       std::string(reinterpret_cast<char*>(&prov_handle),
                   sizeof(NCRYPT_PROV_HANDLE))},
  };
}

}  // namespace

Object::Object(std::string kms_key_name, std::unique_ptr<KmsClient> client,
               absl::flat_hash_map<std::wstring, std::string> info)
    : kms_key_name_(kms_key_name),
      kms_client_(std::move(client)),
      key_info_(info) {}

absl::StatusOr<Object*> Object::New(NCRYPT_PROV_HANDLE prov_handle,
                                    std::string key_name) {
  ASSIGN_OR_RETURN(std::unique_ptr<KmsClient> client,
                   NewKmsClient(prov_handle));
  ASSIGN_OR_RETURN(auto algorithm, GetKeyAlgorithm(*client, key_name));
  ASSIGN_OR_RETURN(AlgorithmDetails alg_details, GetDetails(algorithm));
  auto info = BuildInfo(prov_handle, key_name, alg_details);

  // using `new` to invoke a private constructor
  return new Object(key_name, std::move(client), info);
}

absl::StatusOr<std::string_view> Object::GetProperty(std::wstring_view name) {
  auto it = key_info_.find(name);
  if (it == key_info_.end()) {
    return NewError(absl::StatusCode::kNotFound,
                    "unsupported property specified", NTE_NOT_SUPPORTED,
                    SOURCE_LOCATION);
  }
  return it->second;
}

}  // namespace cloud_kms::kmscng
