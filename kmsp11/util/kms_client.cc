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
                               absl::Time rpc_deadline) {
  // See https://cloud.google.com/kms/docs/grpc
  ctx->AddMetadata("x-goog-request-params",
                   absl::StrCat(relative_resource, "=", resource_name));
  ctx->set_deadline(absl::ToChronoTime(rpc_deadline));

  // note this should be unset for CreateCKV and ImportCKV
  ctx->set_idempotent(true);
}

static void AddContextSettings(grpc::ClientContext* ctx,
                               absl::string_view relative_resource,
                               absl::string_view resource_name,
                               absl::Duration rpc_timeout) {
  AddContextSettings(ctx, relative_resource, resource_name,
                     absl::Now() + rpc_timeout);
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

absl::StatusOr<kms_v1::AsymmetricDecryptResponse> KmsClient::AsymmetricDecrypt(
    const kms_v1::AsymmetricDecryptRequest& request) const {
  grpc::ClientContext ctx;
  AddContextSettings(&ctx, "name", request.name(), rpc_timeout_);

  kms_v1::AsymmetricDecryptResponse response;
  RETURN_IF_ERROR(kms_stub_->AsymmetricDecrypt(&ctx, request, &response));
  return response;
}

absl::StatusOr<kms_v1::AsymmetricSignResponse> KmsClient::AsymmetricSign(
    const kms_v1::AsymmetricSignRequest& request) const {
  grpc::ClientContext ctx;
  AddContextSettings(&ctx, "name", request.name(), rpc_timeout_);

  kms_v1::AsymmetricSignResponse response;
  RETURN_IF_ERROR(kms_stub_->AsymmetricSign(&ctx, request, &response));
  return response;
}

absl::StatusOr<kms_v1::CryptoKey> KmsClient::CreateCryptoKey(
    const kms_v1::CreateCryptoKeyRequest& request) const {
  grpc::ClientContext ctx;
  AddContextSettings(&ctx, "parent", request.parent(), rpc_timeout_);
  ctx.set_idempotent(false);

  kms_v1::CryptoKey response;
  RETURN_IF_ERROR(kms_stub_->CreateCryptoKey(&ctx, request, &response));
  return response;
}

absl::StatusOr<CryptoKeyAndVersion>
KmsClient::CreateCryptoKeyAndWaitForFirstVersion(
    const kms_v1::CreateCryptoKeyRequest& request) const {
  absl::Time deadline = absl::Now() + rpc_timeout_;

  ASSIGN_OR_RETURN(kms_v1::CryptoKey ck, CreateCryptoKey(request));

  kms_v1::GetCryptoKeyVersionRequest get_ckv_req;
  get_ckv_req.set_name(ck.name() + "/cryptoKeyVersions/1");

  kms_v1::CryptoKeyVersion ckv;
  if (ck.has_primary()) {
    ckv = ck.primary();
  } else {
    grpc::ClientContext ctx;
    AddContextSettings(&ctx, "name", get_ckv_req.name(), deadline);

    RETURN_IF_ERROR(kms_stub_->GetCryptoKeyVersion(&ctx, get_ckv_req, &ckv));
  }

  while (ckv.state() == kms_v1::CryptoKeyVersion::PENDING_GENERATION) {
    // TODO(bdhess): Investigate options for sane backoff outside of google3.
    absl::SleepFor(absl::Seconds(1));

    grpc::ClientContext ctx;
    AddContextSettings(&ctx, "name", get_ckv_req.name(), deadline);

    RETURN_IF_ERROR(kms_stub_->GetCryptoKeyVersion(&ctx, get_ckv_req, &ckv));
  }

  return CryptoKeyAndVersion{ck, ckv};
}

absl::StatusOr<kms_v1::PublicKey> KmsClient::GetPublicKey(
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