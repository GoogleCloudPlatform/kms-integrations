#include "kmsp11/util/kms_client.h"

#include "absl/strings/str_cat.h"
#include "absl/strings/str_format.h"
#include "absl/time/clock.h"
#include "grpcpp/client_context.h"
#include "grpcpp/create_channel.h"
#include "grpcpp/security/credentials.h"
#include "kmsp11/util/status_macros.h"
#include "kmsp11/version.h"

namespace kmsp11 {
namespace {

static void AddContextSettings(grpc::ClientContext* ctx,
                               absl::string_view relative_resource,
                               absl::string_view resource_name,
                               absl::Duration rpc_timeout) {
  // See https://cloud.google.com/kms/docs/grpc
  ctx->AddMetadata("x-goog-request-params",
                   absl::StrCat(relative_resource, "=", resource_name));
  ctx->set_deadline(absl::ToChronoTime(absl::Now() + rpc_timeout));

  // note this should be unset for CreateCKV and ImportCKV
  ctx->set_idempotent(true);
}

}  // namespace

KmsClient::KmsClient(absl::string_view endpoint_address,
                     const std::shared_ptr<grpc::ChannelCredentials>& creds,
                     absl::Duration rpc_timeout)
    : rpc_timeout_(rpc_timeout) {
  grpc::ChannelArguments args;
  // Registered in Concord
  // //google3/cloud/analysis/concord/configs/api/attribution-prod/tools.yaml
  args.SetUserAgentPrefix(absl::StrFormat(
      "cloud-kms-pkcs11/%d.%d", kLibraryVersion.major, kLibraryVersion.minor));

  std::shared_ptr<grpc::Channel> channel =
      grpc::CreateCustomChannel(std::string(endpoint_address), creds, args);

  kms_stub_ = kms_v1::KeyManagementService::NewStub(channel);
}

StatusOr<kms_v1::AsymmetricDecryptResponse> KmsClient::AsymmetricDecrypt(
    const kms_v1::AsymmetricDecryptRequest& request) const {
  grpc::ClientContext ctx;
  AddContextSettings(&ctx, "name", request.name(), rpc_timeout_);

  kms_v1::AsymmetricDecryptResponse response;
  RETURN_IF_ERROR(kms_stub_->AsymmetricDecrypt(&ctx, request, &response));
  return response;
}

StatusOr<kms_v1::PublicKey> KmsClient::GetPublicKey(
    const kms_v1::GetPublicKeyRequest& request) const {
  grpc::ClientContext ctx;
  AddContextSettings(&ctx, "name", request.name(), rpc_timeout_);

  kms_v1::PublicKey response;
  RETURN_IF_ERROR(kms_stub_->GetPublicKey(&ctx, request, &response));
  return response;
}

CryptoKeysRange KmsClient::ListCryptoKeys(
    const kms_v1::ListCryptoKeysRequest& request) const {
  return CryptoKeysRange(
      request,
      [this](const kms_v1::ListCryptoKeysRequest& request)
          -> google::cloud::StatusOr<kms_v1::ListCryptoKeysResponse> {
        grpc::ClientContext ctx;
        AddContextSettings(&ctx, "parent", request.parent(), rpc_timeout_);

        kms_v1::ListCryptoKeysResponse response;
        grpc::Status result =
            kms_stub_->ListCryptoKeys(&ctx, request, &response);
        if (!result.ok()) {
          return google::cloud::Status(
              google::cloud::StatusCode(result.error_code()),
              result.error_message());
        }
        return response;
      },
      [](kms_v1::ListCryptoKeysResponse response)
          -> std::vector<kms_v1::CryptoKey> {
        std::vector<kms_v1::CryptoKey> result(response.crypto_keys_size());
        auto& keys = *response.mutable_crypto_keys();
        std::move(keys.begin(), keys.end(), result.begin());
        return result;
      });
}

CryptoKeyVersionsRange KmsClient::ListCryptoKeyVersions(
    const kms_v1::ListCryptoKeyVersionsRequest& request) const {
  return CryptoKeyVersionsRange(
      request,
      [this](const kms_v1::ListCryptoKeyVersionsRequest& request)
          -> ::google::cloud::StatusOr<kms_v1::ListCryptoKeyVersionsResponse> {
        grpc::ClientContext ctx;
        AddContextSettings(&ctx, "parent", request.parent(), rpc_timeout_);

        kms_v1::ListCryptoKeyVersionsResponse response;
        grpc::Status result =
            kms_stub_->ListCryptoKeyVersions(&ctx, request, &response);
        if (!result.ok()) {
          return google::cloud::Status(
              google::cloud::StatusCode(result.error_code()),
              result.error_message());
        }
        return response;
      },
      [](kms_v1::ListCryptoKeyVersionsResponse response)
          -> std::vector<kms_v1::CryptoKeyVersion> {
        std::vector<kms_v1::CryptoKeyVersion> result(
            response.crypto_key_versions_size());
        auto& versions = *response.mutable_crypto_key_versions();
        std::move(versions.begin(), versions.end(), result.begin());
        return result;
      });
}

}  // namespace kmsp11