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

#include "kmsp11/session.h"

#include <regex>

#include "kmsp11/kmsp11.h"
#include "kmsp11/util/errors.h"
#include "kmsp11/util/kms_client.h"
#include "kmsp11/util/status_macros.h"

namespace kmsp11 {
namespace {

absl::Status SessionReadOnlyError(const SourceLocation& source_location) {
  return NewError(absl::StatusCode::kFailedPrecondition, "session is read-only",
                  CKR_SESSION_READ_ONLY, source_location);
}

struct KeyGenerationParams {
  std::string label;
  AlgorithmDetails algorithm;
};

absl::StatusOr<KeyGenerationParams> ExtractKeyGenerationParams(
    absl::Span<const CK_ATTRIBUTE> prv_template) {
  absl::optional<std::string> label;
  absl::optional<kms_v1::CryptoKeyVersion::CryptoKeyVersionAlgorithm> algorithm;

  for (const CK_ATTRIBUTE& attr : prv_template) {
    switch (attr.type) {
      case CKA_LABEL:
        label =
            std::string(reinterpret_cast<char*>(attr.pValue), attr.ulValueLen);
        static std::regex* label_regexp = new std::regex("[a-zA-Z0-9_-]{1,63}");
        if (!std::regex_match(*label, *label_regexp)) {
          return NewInvalidArgumentError(
              "CKA_LABEL must be a valid Cloud KMS CryptoKey ID",
              CKR_ATTRIBUTE_VALUE_INVALID, SOURCE_LOCATION);
        }

        break;
      case CKA_KMS_ALGORITHM:
        if (attr.ulValueLen != sizeof(CK_ULONG)) {
          return NewInvalidArgumentError(
              absl::StrFormat("CKA_KMS_ALGORITHM value should be CK_ULONG "
                              "(size=%d, got=%d)",
                              sizeof(CK_ULONG), attr.ulValueLen),
              CKR_ATTRIBUTE_VALUE_INVALID, SOURCE_LOCATION);
        }
        algorithm = kms_v1::CryptoKeyVersion::CryptoKeyVersionAlgorithm(
            *static_cast<CK_ULONG*>(attr.pValue));
        break;
      default:
        return NewInvalidArgumentError(
            absl::StrFormat(
                "this token does not permit specifying attribute type %#x",
                attr.type),
            CKR_TEMPLATE_INCONSISTENT, SOURCE_LOCATION);
    }
  }

  if (!label.has_value()) {
    return NewInvalidArgumentError(
        "CKA_LABEL must be specified for the private key",
        CKR_TEMPLATE_INCOMPLETE, SOURCE_LOCATION);
  }
  if (!algorithm.has_value()) {
    return NewInvalidArgumentError(
        "CKA_KMS_ALGORITHM must be specified for the private key",
        CKR_TEMPLATE_INCOMPLETE, SOURCE_LOCATION);
  }

  absl::StatusOr<AlgorithmDetails> algorithm_details = GetDetails(*algorithm);
  if (!algorithm_details.ok()) {
    return NewInvalidArgumentError(algorithm_details.status().message(),
                                   CKR_ATTRIBUTE_VALUE_INVALID,
                                   SOURCE_LOCATION);
  }

  return KeyGenerationParams{*label, *algorithm_details};
}

absl::StatusOr<kms_v1::CryptoKeyVersion> CreateNewVersionOfExistingKey(
    const KmsClient& client, const kms_v1::CryptoKey& crypto_key,
    const KeyGenerationParams& prv_gen_params) {
  if (crypto_key.purpose() != prv_gen_params.algorithm.purpose ||
      crypto_key.version_template().algorithm() !=
          prv_gen_params.algorithm.algorithm ||
      crypto_key.version_template().protection_level() != kms_v1::HSM) {
    return NewError(
        absl::StatusCode::kInvalidArgument,
        absl::StrFormat("key attribute mismatch when attempting to create "
                        "new version of existing key: "
                        "current purpose=%d, requested purpose=%d; "
                        "current algorithm=%d, requested algorithm=%d; "
                        "current protection_level=%d, "
                        "requested protection_level=%d",
                        crypto_key.purpose(), prv_gen_params.algorithm.purpose,
                        crypto_key.version_template().algorithm(),
                        prv_gen_params.algorithm.algorithm,
                        crypto_key.version_template().protection_level(),
                        kms_v1::HSM),
        CKR_ARGUMENTS_BAD, SOURCE_LOCATION);
  }
  kms_v1::CreateCryptoKeyVersionRequest req;
  req.set_parent(crypto_key.name());
  return client.CreateCryptoKeyVersionAndWait(req);
}

absl::StatusOr<CryptoKeyAndVersion> CreateKeyAndVersion(
    const KmsClient& client, absl::string_view key_ring_name,
    const KeyGenerationParams& prv_gen_params,
    bool experimental_create_multiple_versions) {
  if (experimental_create_multiple_versions) {
    kms_v1::GetCryptoKeyRequest req;
    req.set_name(
        absl::StrCat(key_ring_name, "/cryptoKeys/", prv_gen_params.label));
    absl::StatusOr<kms_v1::CryptoKey> ck = client.GetCryptoKey(req);
    switch (ck.status().code()) {
      case absl::StatusCode::kOk: {
        ASSIGN_OR_RETURN(
            kms_v1::CryptoKeyVersion ckv,
            CreateNewVersionOfExistingKey(client, *ck, prv_gen_params));
        return CryptoKeyAndVersion{*ck, ckv};
      }
      case absl::StatusCode::kNotFound:
        // The CryptoKey doesn't exist; continue on to create it.
        break;
      default:
        return ck.status();
    }
  }

  kms_v1::CreateCryptoKeyRequest req;
  req.set_parent(std::string(key_ring_name));
  req.set_crypto_key_id(prv_gen_params.label);
  req.mutable_crypto_key()->set_purpose(prv_gen_params.algorithm.purpose);
  req.mutable_crypto_key()->mutable_version_template()->set_algorithm(
      prv_gen_params.algorithm.algorithm);
  req.mutable_crypto_key()->mutable_version_template()->set_protection_level(
      kms_v1::HSM);

  absl::StatusOr<CryptoKeyAndVersion> key_and_version =
      client.CreateCryptoKeyAndWaitForFirstVersion(req);
  if (absl::IsAlreadyExists(key_and_version.status())) {
    if (experimental_create_multiple_versions) {
      // TODO(bdhess): If we choose to make this experiment a full-fledged
      // feature, we should gracefully handle the case where the CryptoKey is
      // created by another (thread|process|caller) while this request is in
      // flight.
      // That recursive logic will be sort of ugly and complicated; just
      // returning CKR_DEVICE_ERROR/AlreadyExists here seems fine for the
      // purposes of the experiment.
      return key_and_version.status();
    }
    return NewError(absl::StatusCode::kAlreadyExists,
                    absl::StrFormat("key with label %s already exists: %s",
                                    prv_gen_params.label,
                                    key_and_version.status().message()),
                    CKR_ARGUMENTS_BAD, SOURCE_LOCATION);
  }
  return key_and_version;
}

}  // namespace

CK_SESSION_INFO Session::info() const {
  bool is_read_write = session_type_ == SessionType::kReadWrite;

  CK_STATE state;
  if (token_->is_logged_in()) {
    state = is_read_write ? CKS_RW_USER_FUNCTIONS : CKS_RO_USER_FUNCTIONS;
  } else {
    state = is_read_write ? CKS_RW_PUBLIC_SESSION : CKS_RO_PUBLIC_SESSION;
  }

  CK_FLAGS flags = CKF_SERIAL_SESSION;
  if (is_read_write) {
    flags |= CKF_RW_SESSION;
  }

  return CK_SESSION_INFO{
      token_->slot_id(),  // slotID
      state,              // state
      flags,              // flags
      0,                  // ulDeviceError
  };
}

void Session::ReleaseOperation() {
  absl::MutexLock l(&op_mutex_);
  op_ = absl::nullopt;
}

absl::Status Session::FindObjectsInit(
    absl::Span<const CK_ATTRIBUTE> attributes) {
  absl::MutexLock l(&op_mutex_);

  if (op_.has_value()) {
    return OperationActiveError(SOURCE_LOCATION);
  }

  std::vector<CK_OBJECT_HANDLE> results =
      token_->FindObjects([&attributes](const Object& o) -> bool {
        for (const CK_ATTRIBUTE& attr : attributes) {
          if (!o.attributes().Contains(attr)) {
            return false;
          }
        }
        return true;
      });

  op_ = FindOp(results);
  return absl::OkStatus();
}

absl::StatusOr<absl::Span<const CK_OBJECT_HANDLE>> Session::FindObjects(
    size_t max_count) {
  absl::MutexLock l(&op_mutex_);

  if (!op_.has_value() || !absl::holds_alternative<FindOp>(op_.value())) {
    return OperationNotInitializedError("find", SOURCE_LOCATION);
  }

  FindOp& op = absl::get<FindOp>(op_.value());
  return op.Next(max_count);
}

absl::Status Session::FindObjectsFinal() {
  absl::MutexLock l(&op_mutex_);

  if (!op_.has_value() || !absl::holds_alternative<FindOp>(op_.value())) {
    return OperationNotInitializedError("find", SOURCE_LOCATION);
  }

  op_ = absl::nullopt;
  return absl::OkStatus();
}

absl::Status Session::DecryptInit(std::shared_ptr<Object> key,
                                  CK_MECHANISM* mechanism) {
  absl::MutexLock l(&op_mutex_);

  if (op_.has_value()) {
    return OperationActiveError(SOURCE_LOCATION);
  }

  ASSIGN_OR_RETURN(op_, NewDecryptOp(key, mechanism));
  return absl::OkStatus();
}

absl::StatusOr<absl::Span<const uint8_t>> Session::Decrypt(
    absl::Span<const uint8_t> ciphertext) {
  absl::MutexLock l(&op_mutex_);

  if (!op_.has_value() || !absl::holds_alternative<DecryptOp>(op_.value())) {
    return OperationNotInitializedError("decrypt", SOURCE_LOCATION);
  }

  return absl::get<DecryptOp>(op_.value())->Decrypt(kms_client_, ciphertext);
}

absl::Status Session::EncryptInit(std::shared_ptr<Object> key,
                                  CK_MECHANISM* mechanism) {
  absl::MutexLock l(&op_mutex_);

  if (op_.has_value()) {
    return OperationActiveError(SOURCE_LOCATION);
  }

  ASSIGN_OR_RETURN(op_, NewEncryptOp(key, mechanism));
  return absl::OkStatus();
}

absl::StatusOr<absl::Span<const uint8_t>> Session::Encrypt(
    absl::Span<const uint8_t> plaintext) {
  absl::MutexLock l(&op_mutex_);

  if (!op_.has_value() || !absl::holds_alternative<EncryptOp>(op_.value())) {
    return OperationNotInitializedError("encrypt", SOURCE_LOCATION);
  }

  return absl::get<EncryptOp>(op_.value())->Encrypt(kms_client_, plaintext);
}

absl::Status Session::SignInit(std::shared_ptr<Object> key,
                               CK_MECHANISM* mechanism) {
  absl::MutexLock l(&op_mutex_);

  if (op_.has_value()) {
    return OperationActiveError(SOURCE_LOCATION);
  }

  ASSIGN_OR_RETURN(op_, NewSignOp(key, mechanism));
  return absl::OkStatus();
}

absl::Status Session::Sign(absl::Span<const uint8_t> digest,
                           absl::Span<uint8_t> signature) {
  absl::MutexLock l(&op_mutex_);

  if (!op_.has_value() || !absl::holds_alternative<SignOp>(op_.value())) {
    return OperationNotInitializedError("sign", SOURCE_LOCATION);
  }

  return absl::get<SignOp>(op_.value())->Sign(kms_client_, digest, signature);
}

absl::StatusOr<size_t> Session::SignatureLength() {
  absl::MutexLock l(&op_mutex_);

  if (!op_.has_value() || !absl::holds_alternative<SignOp>(op_.value())) {
    return OperationNotInitializedError("sign", SOURCE_LOCATION);
  }

  return absl::get<SignOp>(op_.value())->signature_length();
}

absl::Status Session::VerifyInit(std::shared_ptr<Object> key,
                                 CK_MECHANISM* mechanism) {
  absl::MutexLock l(&op_mutex_);

  if (op_.has_value()) {
    return OperationActiveError(SOURCE_LOCATION);
  }

  ASSIGN_OR_RETURN(op_, NewVerifyOp(key, mechanism));
  return absl::OkStatus();
}

absl::Status Session::Verify(absl::Span<const uint8_t> digest,
                             absl::Span<const uint8_t> signature) {
  absl::MutexLock l(&op_mutex_);

  if (!op_.has_value() || !absl::holds_alternative<VerifyOp>(op_.value())) {
    return OperationNotInitializedError("verify", SOURCE_LOCATION);
  }

  return absl::get<VerifyOp>(op_.value())
      ->Verify(kms_client_, digest, signature);
}

absl::StatusOr<AsymmetricHandleSet> Session::GenerateKeyPair(
    const CK_MECHANISM& mechanism,
    absl::Span<const CK_ATTRIBUTE> public_key_attrs,
    absl::Span<const CK_ATTRIBUTE> private_key_attrs,
    bool experimental_create_multiple_versions) {
  if (session_type_ == SessionType::kReadOnly) {
    return SessionReadOnlyError(SOURCE_LOCATION);
  }

  switch (mechanism.mechanism) {
    case CKM_RSA_PKCS_KEY_PAIR_GEN:
    case CKM_EC_KEY_PAIR_GEN:
      break;
    default:
      return InvalidMechanismError(mechanism.mechanism, "GenerateKeyPair",
                                   SOURCE_LOCATION);
  }
  if (mechanism.pParameter || mechanism.ulParameterLen > 0) {
    return InvalidMechanismParamError(
        "key generation mechanisms do not take parameters", SOURCE_LOCATION);
  }

  if (!public_key_attrs.empty()) {
    return NewInvalidArgumentError(
        "this token does not accept public key attributes",
        CKR_TEMPLATE_INCONSISTENT, SOURCE_LOCATION);
  }

  ASSIGN_OR_RETURN(KeyGenerationParams prv_gen_params,
                   ExtractKeyGenerationParams(private_key_attrs));

  if (prv_gen_params.algorithm.key_gen_mechanism != mechanism.mechanism) {
    return NewInvalidArgumentError("algorithm mismatches keygen mechanism",
                                   CKR_TEMPLATE_INCONSISTENT, SOURCE_LOCATION);
  }

  ASSIGN_OR_RETURN(
      CryptoKeyAndVersion key_and_version,
      CreateKeyAndVersion(*kms_client_, token_->key_ring_name(), prv_gen_params,
                          experimental_create_multiple_versions));
  RETURN_IF_ERROR(token_->RefreshState(*kms_client_));

  AsymmetricHandleSet result;
  ASSIGN_OR_RETURN(result.public_key_handle,
                   token_->FindSingleObject([&](const Object& o) -> bool {
                     return o.kms_key_name() ==
                                key_and_version.crypto_key_version.name() &&
                            o.object_class() == CKO_PUBLIC_KEY;
                   }));
  ASSIGN_OR_RETURN(result.private_key_handle,
                   token_->FindSingleObject([&](const Object& o) -> bool {
                     return o.kms_key_name() ==
                                key_and_version.crypto_key_version.name() &&
                            o.object_class() == CKO_PRIVATE_KEY;
                   }));
  return result;
}

absl::Status Session::DestroyObject(std::shared_ptr<Object> key) {
  if (session_type_ == SessionType::kReadOnly) {
    return SessionReadOnlyError(SOURCE_LOCATION);
  }

  CK_BBOOL ck_true = CK_TRUE;
  if (!key->attributes().Contains(
          CK_ATTRIBUTE{CKA_DESTROYABLE, &ck_true, sizeof(ck_true)})) {
    return FailedPreconditionError("the selected object is not destroyable",
                                   CKR_ACTION_PROHIBITED, SOURCE_LOCATION);
  }

  kms_v1::DestroyCryptoKeyVersionRequest req;
  req.set_name(std::string(key->kms_key_name()));
  RETURN_IF_ERROR(kms_client_->DestroyCryptoKeyVersion(req));
  RETURN_IF_ERROR(token_->RefreshState(*kms_client_));
  return absl::OkStatus();
}

}  // namespace kmsp11
