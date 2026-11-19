// Copyright 2026 Google LLC
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

#include "kmsp11/operation/ml_dsa.h"

#include <string>

#include "absl/strings/str_format.h"
#include "common/kms_client.h"
#include "common/status_macros.h"
#include "kmsp11/operation/preconditions.h"
#include "kmsp11/util/errors.h"
#include "kmsp11/util/ml_dsa.h"

namespace cloud_kms::kmsp11 {
namespace {

struct MlDsaMechanismParams {
  CK_HEDGE_TYPE hedge_variant = CKH_HEDGE_PREFERRED;
  std::string context;
};

absl::StatusOr<MlDsaMechanismParams> ParseMechanismParams(
    const CK_MECHANISM* mechanism) {
  MlDsaMechanismParams result;
  if (!mechanism->pParameter && mechanism->ulParameterLen == 0) {
    return result;
  }
  if (!mechanism->pParameter ||
      mechanism->ulParameterLen != sizeof(CK_SIGN_ADDITIONAL_CONTEXT)) {
    return InvalidMechanismParamError(
        "mechanism parameters must be of type CK_SIGN_ADDITIONAL_CONTEXT",
        SOURCE_LOCATION);
  }

  auto* params =
      static_cast<const CK_SIGN_ADDITIONAL_CONTEXT*>(mechanism->pParameter);
  switch (params->hedgeVariant) {
    case CKH_HEDGE_PREFERRED:
    case CKH_HEDGE_REQUIRED:
    case CKH_DETERMINISTIC_REQUIRED:
      break;
    default:
      return InvalidMechanismParamError(
          absl::StrFormat("unknown hedgeVariant %#x", params->hedgeVariant),
          SOURCE_LOCATION);
  }
  if (params->ulContextLen > 255) {
    return InvalidMechanismParamError(
        "ML-DSA context strings may not exceed 255 bytes", SOURCE_LOCATION);
  }
  if (params->ulContextLen > 0 && !params->pContext) {
    return InvalidMechanismParamError(
        "pContext must be set when ulContextLen is nonzero", SOURCE_LOCATION);
  }

  result.hedge_variant = params->hedgeVariant;
  if (params->ulContextLen > 0) {
    result.context.assign(reinterpret_cast<const char*>(params->pContext),
                          params->ulContextLen);
  }
  return result;
}

absl::StatusOr<MlDsaPublicKey> PublicKeyFromObject(const Object& key) {
  ASSIGN_OR_RETURN(std::string_view der,
                   key.attributes().Value(CKA_PUBLIC_KEY_INFO));
  return ParseMlDsaPublicKeyDer(der);
}

// Accumulates the message for multi-part operations. ML-DSA signs the full
// message (it is not a hash-then-sign scheme), so the parts must be buffered.
absl::Status AppendMessagePart(std::string* buffer,
                               absl::Span<const uint8_t> part) {
  if (part.size() > kMaxMlDsaMessageBytes - buffer->size()) {
    return NewInvalidArgumentError(
        absl::StrFormat("message too long: Cloud KMS ML-DSA signing supports "
                        "messages of at most %d bytes",
                        kMaxMlDsaMessageBytes),
        CKR_DATA_LEN_RANGE, SOURCE_LOCATION);
  }
  buffer->append(reinterpret_cast<const char*>(part.data()), part.size());
  return absl::OkStatus();
}

absl::Span<const uint8_t> AsSpan(std::string_view s) {
  return absl::MakeConstSpan(reinterpret_cast<const uint8_t*>(s.data()),
                             s.size());
}

class MlDsaSigner : public SignerInterface {
 public:
  MlDsaSigner(std::shared_ptr<Object> object, size_t signature_length)
      : object_(object), signature_length_(signature_length) {}

  size_t signature_length() override { return signature_length_; }
  Object* object() override { return object_.get(); }

  absl::Status Sign(KmsClient* client, absl::Span<const uint8_t> data,
                    absl::Span<uint8_t> signature) override {
    if (multipart_started_) {
      return FailedPreconditionError(
          "Sign cannot be used to terminate a multi-part signing operation",
          CKR_FUNCTION_FAILED, SOURCE_LOCATION);
    }
    if (data.size() > kMaxMlDsaMessageBytes) {
      return NewInvalidArgumentError(
          absl::StrFormat("message too long: Cloud KMS ML-DSA signing "
                          "supports messages of at most %d bytes",
                          kMaxMlDsaMessageBytes),
          CKR_DATA_LEN_RANGE, SOURCE_LOCATION);
    }
    return SignMessage(client, data, signature);
  }

  absl::Status SignUpdate(KmsClient* client,
                          absl::Span<const uint8_t> data) override {
    multipart_started_ = true;
    return AppendMessagePart(&buffer_, data);
  }

  absl::Status SignFinal(KmsClient* client,
                         absl::Span<uint8_t> signature) override {
    if (!multipart_started_) {
      return FailedPreconditionError(
          "SignUpdate needs to be called prior to terminating a multi-part "
          "signing operation",
          CKR_FUNCTION_FAILED, SOURCE_LOCATION);
    }
    return SignMessage(client, AsSpan(buffer_), signature);
  }

 private:
  absl::Status SignMessage(KmsClient* client, absl::Span<const uint8_t> data,
                           absl::Span<uint8_t> signature) {
    if (signature.size() != signature_length_) {
      return NewInternalError(
          absl::StrFormat(
              "provided signature buffer has incorrect size (got %d, want %d)",
              signature.size(), signature_length_),
          SOURCE_LOCATION);
    }

    kms_v1::AsymmetricSignRequest req;
    req.set_name(std::string(object_->kms_key_name()));
    req.set_data(std::string(reinterpret_cast<const char*>(data.data()),
                             data.size()));

    ASSIGN_OR_RETURN(kms_v1::AsymmetricSignResponse resp,
                     client->AsymmetricSign(req));
    if (resp.signature().size() != signature_length_) {
      return NewInternalError(
          absl::StrFormat("unexpected signature length (got %d, want %d)",
                          resp.signature().size(), signature_length_),
          SOURCE_LOCATION);
    }
    std::copy(resp.signature().begin(), resp.signature().end(),
              signature.begin());
    return absl::OkStatus();
  }

  std::shared_ptr<Object> object_;
  size_t signature_length_;
  bool multipart_started_ = false;
  std::string buffer_;
};

class MlDsaVerifier : public VerifierInterface {
 public:
  MlDsaVerifier(std::shared_ptr<Object> object, MlDsaPublicKey public_key,
                std::string context)
      : object_(object),
        public_key_(std::move(public_key)),
        context_(std::move(context)) {}

  Object* object() override { return object_.get(); }

  absl::Status Verify(KmsClient* client, absl::Span<const uint8_t> data,
                      absl::Span<const uint8_t> signature) override {
    if (multipart_started_) {
      return FailedPreconditionError(
          "Verify cannot be used to terminate a multi-part verify operation",
          CKR_FUNCTION_FAILED, SOURCE_LOCATION);
    }
    return MlDsaVerify(public_key_, data, AsSpan(context_), signature);
  }

  absl::Status VerifyUpdate(KmsClient* client,
                            absl::Span<const uint8_t> data) override {
    multipart_started_ = true;
    // Verification is local, so it is not subject to the Cloud KMS message
    // size limit.
    buffer_.append(reinterpret_cast<const char*>(data.data()), data.size());
    return absl::OkStatus();
  }

  absl::Status VerifyFinal(KmsClient* client,
                           absl::Span<const uint8_t> signature) override {
    if (!multipart_started_) {
      return FailedPreconditionError(
          "VerifyUpdate needs to be called prior to terminating a multi-part "
          "verify operation",
          CKR_FUNCTION_FAILED, SOURCE_LOCATION);
    }
    return MlDsaVerify(public_key_, AsSpan(buffer_), AsSpan(context_),
                       signature);
  }

 private:
  std::shared_ptr<Object> object_;
  MlDsaPublicKey public_key_;
  std::string context_;
  bool multipart_started_ = false;
  std::string buffer_;
};

}  // namespace

absl::StatusOr<std::unique_ptr<SignerInterface>> NewMlDsaSigner(
    std::shared_ptr<Object> key, const CK_MECHANISM* mechanism) {
  RETURN_IF_ERROR(CheckKeyPreconditions(CKK_ML_DSA, CKO_PRIVATE_KEY,
                                        CKM_ML_DSA, key.get()));
  ASSIGN_OR_RETURN(MlDsaMechanismParams params,
                   ParseMechanismParams(mechanism));

  // Cloud KMS always produces hedged signatures over an empty context.
  if (params.hedge_variant == CKH_DETERMINISTIC_REQUIRED) {
    return InvalidMechanismParamError(
        "Cloud KMS does not support deterministic ML-DSA signing",
        SOURCE_LOCATION);
  }
  if (!params.context.empty()) {
    return InvalidMechanismParamError(
        "Cloud KMS does not support ML-DSA signing with a context string",
        SOURCE_LOCATION);
  }

  ASSIGN_OR_RETURN(MlDsaPublicKey public_key, PublicKeyFromObject(*key));
  ASSIGN_OR_RETURN(MlDsaSizes sizes, GetMlDsaSizes(public_key.parameter_set));
  return std::unique_ptr<SignerInterface>(
      new MlDsaSigner(key, sizes.signature_bytes));
}

absl::StatusOr<std::unique_ptr<VerifierInterface>> NewMlDsaVerifier(
    std::shared_ptr<Object> key, const CK_MECHANISM* mechanism) {
  RETURN_IF_ERROR(
      CheckKeyPreconditions(CKK_ML_DSA, CKO_PUBLIC_KEY, CKM_ML_DSA, key.get()));
  if (!MlDsaVerificationSupported()) {
    return NewInvalidArgumentError(
        "ML-DSA verification is not supported by the crypto library this "
        "module was built with",
        CKR_MECHANISM_INVALID, SOURCE_LOCATION);
  }
  // On verification, hedgeVariant is ignored, and any context is permitted.
  ASSIGN_OR_RETURN(MlDsaMechanismParams params,
                   ParseMechanismParams(mechanism));
  ASSIGN_OR_RETURN(MlDsaPublicKey public_key, PublicKeyFromObject(*key));
  return std::unique_ptr<VerifierInterface>(
      new MlDsaVerifier(key, std::move(public_key), std::move(params.context)));
}

}  // namespace cloud_kms::kmsp11
