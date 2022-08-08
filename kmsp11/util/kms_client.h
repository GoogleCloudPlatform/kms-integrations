/*
 * Copyright 2021 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef KMSP11_UTIL_KMS_CLIENT_H_
#define KMSP11_UTIL_KMS_CLIENT_H_

#include <string_view>

#include "absl/status/statusor.h"
#include "absl/time/clock.h"
#include "absl/time/time.h"
#include "grpcpp/security/credentials.h"
#include "kmsp11/util/kms_v1.h"
#include "kmsp11/util/pagination_range.h"

namespace kmsp11 {

using CryptoKeysRange =
    PaginationRange<kms_v1::CryptoKey, kms_v1::ListCryptoKeysRequest,
                    kms_v1::ListCryptoKeysResponse>;

using CryptoKeyVersionsRange =
    PaginationRange<kms_v1::CryptoKeyVersion,
                    kms_v1::ListCryptoKeyVersionsRequest,
                    kms_v1::ListCryptoKeyVersionsResponse>;

struct CryptoKeyAndVersion {
  kms_v1::CryptoKey crypto_key;
  kms_v1::CryptoKeyVersion crypto_key_version;
};

class KmsClient {
 public:
  KmsClient(std::string_view endpoint_address,
            const std::shared_ptr<grpc::ChannelCredentials>& creds,
            absl::Duration rpc_timeout, std::string_view rpc_feature_flags = "",
            std::string_view user_project_override = "");

  kms_v1::KeyManagementService::Stub* kms_stub() { return kms_stub_.get(); }

  absl::StatusOr<kms_v1::AsymmetricDecryptResponse> AsymmetricDecrypt(
      const kms_v1::AsymmetricDecryptRequest& request) const;

  absl::StatusOr<kms_v1::AsymmetricSignResponse> AsymmetricSign(
      const kms_v1::AsymmetricSignRequest& request) const;

  absl::StatusOr<kms_v1::MacSignResponse> MacSign(
      const kms_v1::MacSignRequest& request) const;

  absl::StatusOr<kms_v1::MacVerifyResponse> MacVerify(
      const kms_v1::MacVerifyRequest& request) const;

  absl::StatusOr<kms_v1::RawDecryptResponse> RawDecrypt(
      kms_v1::RawDecryptRequest& request) const;

  absl::StatusOr<kms_v1::RawEncryptResponse> RawEncrypt(
      kms_v1::RawEncryptRequest& request) const;

  absl::StatusOr<kms_v1::CryptoKey> CreateCryptoKey(
      const kms_v1::CreateCryptoKeyRequest& request) const;

  absl::StatusOr<CryptoKeyAndVersion> CreateCryptoKeyAndWaitForFirstVersion(
      const kms_v1::CreateCryptoKeyRequest& request) const;

  absl::StatusOr<kms_v1::CryptoKeyVersion> CreateCryptoKeyVersionAndWait(
      const kms_v1::CreateCryptoKeyVersionRequest& request) const;

  absl::StatusOr<kms_v1::CryptoKeyVersion> DestroyCryptoKeyVersion(
      const kms_v1::DestroyCryptoKeyVersionRequest& request) const;

  absl::StatusOr<kms_v1::CryptoKey> GetCryptoKey(
      const kms_v1::GetCryptoKeyRequest& request) const;

  absl::StatusOr<kms_v1::PublicKey> GetPublicKey(
      const kms_v1::GetPublicKeyRequest& request) const;

  CryptoKeysRange ListCryptoKeys(
      const kms_v1::ListCryptoKeysRequest& request) const;

  CryptoKeyVersionsRange ListCryptoKeyVersions(
      const kms_v1::ListCryptoKeyVersionsRequest& request) const;

  absl::StatusOr<kms_v1::GenerateRandomBytesResponse> GenerateRandomBytes(
      const kms_v1::GenerateRandomBytesRequest& request) const;

 private:
  absl::Status WaitForGeneration(kms_v1::CryptoKeyVersion& ckv,
                                 absl::Time deadline) const;

  void AddContextSettings(grpc::ClientContext* ctx,
                          std::string_view relative_resource,
                          std::string_view resource_name,
                          absl::Time rpc_deadline) const;

  inline void AddContextSettings(grpc::ClientContext* ctx,
                                 std::string_view relative_resource,
                                 std::string_view resource_name) const {
    return AddContextSettings(ctx, relative_resource, resource_name,
                              absl::Now() + rpc_timeout_);
  }

  std::unique_ptr<kms_v1::KeyManagementService::Stub> kms_stub_;
  const absl::Duration rpc_timeout_;
  const std::string rpc_feature_flags_;
  const std::string user_project_override_;
};

}  // namespace kmsp11

#endif  // KMSP11_UTIL_KMS_CLIENT_H_
