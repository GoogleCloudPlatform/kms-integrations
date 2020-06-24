#ifndef KMSP11_UTIL_KMS_CLIENT_H_
#define KMSP11_UTIL_KMS_CLIENT_H_

#include "absl/strings/string_view.h"
#include "absl/time/time.h"
#include "google/cloud/internal/pagination_range.h"
#include "google/cloud/kms/v1/resources.pb.h"
#include "google/cloud/kms/v1/service.grpc.pb.h"
#include "google/cloud/kms/v1/service.pb.h"
#include "grpcpp/security/credentials.h"
#include "kmsp11/util/status_or.h"

namespace kmsp11 {

// intentionally exported
namespace kms_v1 = ::google::cloud::kms::v1;

using CryptoKeysRange =
    google::cloud::internal::PaginationRange<kms_v1::CryptoKey,
                                             kms_v1::ListCryptoKeysRequest,
                                             kms_v1::ListCryptoKeysResponse>;

using CryptoKeyVersionsRange = google::cloud::internal::PaginationRange<
    kms_v1::CryptoKeyVersion, kms_v1::ListCryptoKeyVersionsRequest,
    kms_v1::ListCryptoKeyVersionsResponse>;

class KmsClient {
 public:
  KmsClient(absl::string_view endpoint_address,
            const std::shared_ptr<grpc::ChannelCredentials>& creds,
            absl::Duration rpc_timeout);

  kms_v1::KeyManagementService::Stub* kms_stub() { return kms_stub_.get(); }

  StatusOr<kms_v1::AsymmetricDecryptResponse> AsymmetricDecrypt(
      const kms_v1::AsymmetricDecryptRequest& request) const;

  StatusOr<kms_v1::PublicKey> GetPublicKey(
      const kms_v1::GetPublicKeyRequest& request) const;

  CryptoKeysRange ListCryptoKeys(
      const kms_v1::ListCryptoKeysRequest& request) const;

  CryptoKeyVersionsRange ListCryptoKeyVersions(
      const kms_v1::ListCryptoKeyVersionsRequest& request) const;

 private:
  std::unique_ptr<kms_v1::KeyManagementService::Stub> kms_stub_;
  absl::Duration rpc_timeout_;
};

}  // namespace kmsp11

#endif  // KMSP11_UTIL_KMS_CLIENT_H_