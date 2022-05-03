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

#include "kmsp11/util/kms_client.h"

#include "absl/strings/str_cat.h"
#include "absl/strings/str_format.h"
#include "grpcpp/client_context.h"
#include "grpcpp/create_channel.h"
#include "grpcpp/security/credentials.h"
#include "kmsp11/openssl.h"
#include "kmsp11/util/backoff.h"
#include "kmsp11/util/kms_client_service_config.h"
#include "kmsp11/util/platform.h"
#include "kmsp11/util/status_macros.h"
#include "kmsp11/version.h"

namespace kmsp11 {
namespace {

// clang-format off
// Sample value:
// `cloud-kms-pkcs11/0.21 (amd64; BoringSSL; Linux/4.15.0-1096-gcp-x86_64; glibc/2.23)`
// clang-format on
std::string ComputeUserAgentPrefix() {
  // Registered in Concord (cl/315314203)
  return absl::StrFormat("cloud-kms-pkcs11/%d.%d (%s; %s%s; %s)",
                         kLibraryVersion.major, kLibraryVersion.minor,
                         GetTargetPlatform(), OpenSSL_version(OPENSSL_VERSION),
                         FIPS_mode() == 1 ? " FIPS" : "",
                         GetHostPlatformInfo());
}

}  // namespace

void KmsClient::AddContextSettings(grpc::ClientContext* ctx,
                                   std::string_view relative_resource,
                                   std::string_view resource_name,
                                   absl::Time rpc_deadline) const {
  // See https://cloud.google.com/kms/docs/grpc
  ctx->AddMetadata("x-goog-request-params",
                   absl::StrCat(relative_resource, "=", resource_name));
  ctx->set_deadline(absl::ToChronoTime(rpc_deadline));

  if (!user_project_override_.empty()) {
    ctx->AddMetadata("x-goog-user-project", user_project_override_);
  }
}

KmsClient::KmsClient(std::string_view endpoint_address,
                     const std::shared_ptr<grpc::ChannelCredentials>& creds,
                     absl::Duration rpc_timeout,
                     std::string_view user_project_override)
    : rpc_timeout_(rpc_timeout), user_project_override_(user_project_override) {
  grpc::ChannelArguments args;
  args.SetUserAgentPrefix(ComputeUserAgentPrefix());
  args.SetServiceConfigJSON(std::string(kDefaultKmsServiceConfig));

  std::shared_ptr<grpc::Channel> channel =
      grpc::CreateCustomChannel(std::string(endpoint_address), creds, args);

  kms_stub_ = kms_v1::KeyManagementService::NewStub(channel);
}

absl::StatusOr<kms_v1::AsymmetricDecryptResponse> KmsClient::AsymmetricDecrypt(
    const kms_v1::AsymmetricDecryptRequest& request) const {
  grpc::ClientContext ctx;
  AddContextSettings(&ctx, "name", request.name());

  kms_v1::AsymmetricDecryptResponse response;
  absl::Status rpc_result =
      ToStatus(kms_stub_->AsymmetricDecrypt(&ctx, request, &response));
  if (!rpc_result.ok()) {
    SetErrorRv(rpc_result, CKR_DEVICE_ERROR);
    return rpc_result;
  }
  return response;
}

absl::StatusOr<kms_v1::AsymmetricSignResponse> KmsClient::AsymmetricSign(
    const kms_v1::AsymmetricSignRequest& request) const {
  grpc::ClientContext ctx;
  AddContextSettings(&ctx, "name", request.name());

  kms_v1::AsymmetricSignResponse response;
  absl::Status rpc_result =
      ToStatus(kms_stub_->AsymmetricSign(&ctx, request, &response));
  if (!rpc_result.ok()) {
    SetErrorRv(rpc_result, CKR_DEVICE_ERROR);
    return rpc_result;
  }
  return response;
}

absl::StatusOr<kms_v1::MacSignResponse> KmsClient::MacSign(
    const kms_v1::MacSignRequest& request) const {
  grpc::ClientContext ctx;
  AddContextSettings(&ctx, "name", request.name());

  kms_v1::MacSignResponse response;
  absl::Status rpc_result =
      ToStatus(kms_stub_->MacSign(&ctx, request, &response));
  if (!rpc_result.ok()) {
    SetErrorRv(rpc_result, CKR_DEVICE_ERROR);
    return rpc_result;
  }
  return response;
}

absl::StatusOr<kms_v1::MacVerifyResponse> KmsClient::MacVerify(
    const kms_v1::MacVerifyRequest& request) const {
  grpc::ClientContext ctx;
  AddContextSettings(&ctx, "name", request.name());

  kms_v1::MacVerifyResponse response;
  absl::Status rpc_result =
      ToStatus(kms_stub_->MacVerify(&ctx, request, &response));
  if (!rpc_result.ok()) {
    SetErrorRv(rpc_result, CKR_DEVICE_ERROR);
    return rpc_result;
  }
  return response;
}

absl::StatusOr<kms_v1::CryptoKey> KmsClient::CreateCryptoKey(
    const kms_v1::CreateCryptoKeyRequest& request) const {
  grpc::ClientContext ctx;
  AddContextSettings(&ctx, "parent", request.parent());

  kms_v1::CryptoKey response;
  absl::Status rpc_result =
      ToStatus(kms_stub_->CreateCryptoKey(&ctx, request, &response));
  if (!rpc_result.ok()) {
    SetErrorRv(rpc_result, CKR_DEVICE_ERROR);
    return rpc_result;
  }
  return response;
}

absl::StatusOr<CryptoKeyAndVersion>
KmsClient::CreateCryptoKeyAndWaitForFirstVersion(
    const kms_v1::CreateCryptoKeyRequest& request) const {
  absl::Time deadline = absl::Now() + rpc_timeout_;

  ASSIGN_OR_RETURN(kms_v1::CryptoKey ck, CreateCryptoKey(request));

  kms_v1::CryptoKeyVersion ckv;
  if (ck.has_primary()) {
    ckv = ck.primary();
  } else {
    std::string name = absl::StrCat(ck.name(), "/cryptoKeyVersions/1");

    grpc::ClientContext ctx;
    AddContextSettings(&ctx, "name", name, deadline);

    kms_v1::GetCryptoKeyVersionRequest get_ckv_req;
    get_ckv_req.set_name(name);

    absl::Status rpc_result =
        ToStatus(kms_stub_->GetCryptoKeyVersion(&ctx, get_ckv_req, &ckv));
    if (!rpc_result.ok()) {
      SetErrorRv(rpc_result, CKR_DEVICE_ERROR);
      return rpc_result;
    }
  }

  RETURN_IF_ERROR(WaitForGeneration(ckv, deadline));
  return CryptoKeyAndVersion{ck, ckv};
}

absl::StatusOr<kms_v1::CryptoKeyVersion>
KmsClient::CreateCryptoKeyVersionAndWait(
    const kms_v1::CreateCryptoKeyVersionRequest& request) const {
  absl::Time deadline = absl::Now() + rpc_timeout_;

  grpc::ClientContext ctx;
  AddContextSettings(&ctx, "parent", request.parent(), deadline);

  kms_v1::CryptoKeyVersion response;
  absl::Status rpc_result =
      ToStatus(kms_stub_->CreateCryptoKeyVersion(&ctx, request, &response));
  if (!rpc_result.ok()) {
    SetErrorRv(rpc_result, CKR_DEVICE_ERROR);
    return rpc_result;
  }
  RETURN_IF_ERROR(WaitForGeneration(response, deadline));
  return response;
}

absl::StatusOr<kms_v1::CryptoKeyVersion> KmsClient::DestroyCryptoKeyVersion(
    const kms_v1::DestroyCryptoKeyVersionRequest& request) const {
  grpc::ClientContext ctx;
  AddContextSettings(&ctx, "name", request.name());

  kms_v1::CryptoKeyVersion response;
  absl::Status rpc_result =
      ToStatus(kms_stub_->DestroyCryptoKeyVersion(&ctx, request, &response));
  if (!rpc_result.ok()) {
    SetErrorRv(rpc_result, CKR_DEVICE_ERROR);
    return rpc_result;
  }
  return response;
}

absl::StatusOr<kms_v1::CryptoKey> KmsClient::GetCryptoKey(
    const kms_v1::GetCryptoKeyRequest& request) const {
  grpc::ClientContext ctx;
  AddContextSettings(&ctx, "name", request.name());

  kms_v1::CryptoKey response;
  absl::Status rpc_result =
      ToStatus(kms_stub_->GetCryptoKey(&ctx, request, &response));
  if (!rpc_result.ok()) {
    SetErrorRv(rpc_result, CKR_DEVICE_ERROR);
    return rpc_result;
  }
  return response;
}

absl::StatusOr<kms_v1::PublicKey> KmsClient::GetPublicKey(
    const kms_v1::GetPublicKeyRequest& request) const {
  grpc::ClientContext ctx;
  AddContextSettings(&ctx, "name", request.name());

  kms_v1::PublicKey response;
  absl::Status rpc_result =
      ToStatus(kms_stub_->GetPublicKey(&ctx, request, &response));
  if (!rpc_result.ok()) {
    SetErrorRv(rpc_result, CKR_DEVICE_ERROR);
    return rpc_result;
  }
  return response;
}

CryptoKeysRange KmsClient::ListCryptoKeys(
    const kms_v1::ListCryptoKeysRequest& request) const {
  return CryptoKeysRange(
      request,
      [this](const kms_v1::ListCryptoKeysRequest& request)
          -> absl::StatusOr<kms_v1::ListCryptoKeysResponse> {
        grpc::ClientContext ctx;
        AddContextSettings(&ctx, "parent", request.parent());

        kms_v1::ListCryptoKeysResponse response;
        absl::Status rpc_result =
            ToStatus(kms_stub_->ListCryptoKeys(&ctx, request, &response));
        if (!rpc_result.ok()) {
          SetErrorRv(rpc_result, CKR_DEVICE_ERROR);
          return rpc_result;
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
          -> absl::StatusOr<kms_v1::ListCryptoKeyVersionsResponse> {
        grpc::ClientContext ctx;
        AddContextSettings(&ctx, "parent", request.parent());

        kms_v1::ListCryptoKeyVersionsResponse response;
        absl::Status rpc_result = ToStatus(
            kms_stub_->ListCryptoKeyVersions(&ctx, request, &response));
        if (!rpc_result.ok()) {
          SetErrorRv(rpc_result, CKR_DEVICE_ERROR);
          return rpc_result;
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

absl::StatusOr<kms_v1::GenerateRandomBytesResponse>
KmsClient::GenerateRandomBytes(
    const kms_v1::GenerateRandomBytesRequest& request) const {
  grpc::ClientContext ctx;
  AddContextSettings(&ctx, "location", request.location());

  kms_v1::GenerateRandomBytesResponse response;
  absl::Status rpc_result =
      ToStatus(kms_stub_->GenerateRandomBytes(&ctx, request, &response));
  if (!rpc_result.ok()) {
    SetErrorRv(rpc_result, CKR_DEVICE_ERROR);
    return rpc_result;
  }
  return response;
}

absl::Status KmsClient::WaitForGeneration(kms_v1::CryptoKeyVersion& ckv,
                                          absl::Time deadline) const {
  // The time for newly generated HSM keys to flip to enabled in (real) KMS
  // varies from 10-40ish milliseconds depending on key type.
  constexpr absl::Duration kMinDelay = absl::Milliseconds(20);
  constexpr absl::Duration kMaxDelay = absl::Seconds(1);

  int tries = 0;
  while (ckv.state() == kms_v1::CryptoKeyVersion::PENDING_GENERATION) {
    absl::SleepFor(ComputeBackoff(kMinDelay, kMaxDelay, tries++));

    grpc::ClientContext ctx;
    AddContextSettings(&ctx, "name", ckv.name(), deadline);

    kms_v1::GetCryptoKeyVersionRequest req;
    req.set_name(ckv.name());
    absl::Status rpc_result =
        ToStatus(kms_stub_->GetCryptoKeyVersion(&ctx, req, &ckv));
    if (!rpc_result.ok()) {
      SetErrorRv(rpc_result, CKR_DEVICE_ERROR);
      return rpc_result;
    }
  }
  return absl::OkStatus();
}

}  // namespace kmsp11
