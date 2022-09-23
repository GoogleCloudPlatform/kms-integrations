// Copyright 2022 Google LLC
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

#include "kmsp11/operation/aes_ctr.h"

#include "absl/cleanup/cleanup.h"
#include "kmsp11/kmsp11.h"
#include "kmsp11/object.h"
#include "kmsp11/operation/preconditions.h"
#include "kmsp11/util/crypto_utils.h"
#include "kmsp11/util/errors.h"
#include "kmsp11/util/status_macros.h"
#include "kmsp11/util/string_utils.h"

namespace kmsp11 {
namespace {

constexpr size_t kMaxPlaintextBytes = 64 * 1024;
constexpr size_t kMaxCiphertextBytes = kMaxPlaintextBytes + 16;

absl::StatusOr<CK_AES_CTR_PARAMS> ExtractCtrParameters(
    void* parameters, CK_ULONG parameters_size) {
  if (parameters_size != sizeof(CK_AES_CTR_PARAMS)) {
    return InvalidMechanismParamError(
        "mechanism parameters must be of type CK_AES_CTR_PARAMS",
        SOURCE_LOCATION);
  }

  CK_AES_CTR_PARAMS params = *reinterpret_cast<CK_AES_CTR_PARAMS*>(parameters);

  if (params.ulCounterBits != 128) {
    return InvalidMechanismParamError(
        absl::StrFormat(
            "invalid number of counter block bits: got %d; want 128",
            params.ulCounterBits),
        SOURCE_LOCATION);
  }

  return params;
}

// An implementation of EncrypterInterface that generates AES-CTR ciphertexts
// using Cloud KMS.
class AesCtrEncrypter : public EncrypterInterface {
 public:
  static absl::StatusOr<std::unique_ptr<EncrypterInterface>> New(
      std::shared_ptr<Object> key, const CK_MECHANISM* mechanism);

  absl::StatusOr<absl::Span<const uint8_t>> Encrypt(
      KmsClient* client, absl::Span<const uint8_t> ciphertext) override;
  absl::Status EncryptUpdate(KmsClient* client,
                             absl::Span<const uint8_t> plaintext_part) override;
  absl::StatusOr<absl::Span<const uint8_t>> EncryptFinal(
      KmsClient* client) override;

  virtual ~AesCtrEncrypter() {}

 private:
  AesCtrEncrypter(std::shared_ptr<Object> object, CK_BYTE cb[])
      : object_(object) {
    memcpy(cb_, cb, sizeof(cb_));
  }

  std::shared_ptr<Object> object_;
  CK_BYTE cb_[16];
  std::optional<std::vector<uint8_t>> plaintext_;
  std::vector<uint8_t> ciphertext_;
};

absl::StatusOr<std::unique_ptr<EncrypterInterface>> AesCtrEncrypter::New(
    std::shared_ptr<Object> key, const CK_MECHANISM* mechanism) {
  RETURN_IF_ERROR(
      CheckKeyPreconditions(CKK_AES, CKO_SECRET_KEY, CKM_AES_CTR, key.get()));

  ASSIGN_OR_RETURN(
      CK_AES_CTR_PARAMS params,
      ExtractCtrParameters(mechanism->pParameter, mechanism->ulParameterLen));

  return std::unique_ptr<EncrypterInterface>(
      new AesCtrEncrypter(key, params.cb));
}

absl::StatusOr<absl::Span<const uint8_t>> AesCtrEncrypter::Encrypt(
    KmsClient* client, absl::Span<const uint8_t> plaintext) {
  if (plaintext_) {
    return FailedPreconditionError(
        "Encrypt cannot be used to terminate a multi-part encryption operation",
        CKR_FUNCTION_FAILED, SOURCE_LOCATION);
  }

  if (plaintext.size() > kMaxPlaintextBytes) {
    return NewInvalidArgumentError(
        absl::StrFormat(
            "plaintext length (%d bytes) exceeds maximum allowed %d",
            plaintext.size(), kMaxPlaintextBytes),
        CKR_DATA_LEN_RANGE, SOURCE_LOCATION);
  }

  kms_v1::RawEncryptRequest req;
  req.set_name(std::string(object_->kms_key_name()));
  req.set_plaintext(std::string(reinterpret_cast<const char*>(plaintext.data()),
                                plaintext.size()));
  req.set_initialization_vector(
      std::string(reinterpret_cast<const char*>(cb_), sizeof(cb_)));

  ASSIGN_OR_RETURN(kms_v1::RawEncryptResponse resp, client->RawEncrypt(req));

  ciphertext_.resize(resp.ciphertext().size());
  std::copy_n(resp.ciphertext().begin(), resp.ciphertext().size(),
              ciphertext_.begin());

  return absl::MakeConstSpan(ciphertext_);
}

absl::Status AesCtrEncrypter::EncryptUpdate(
    KmsClient* client, absl::Span<const uint8_t> plaintext_part) {
  if (!plaintext_) {
    plaintext_.emplace(plaintext_part.begin(), plaintext_part.end());
    return absl::OkStatus();
  }

  if (plaintext_part.size() + plaintext_->size() > kMaxPlaintextBytes) {
    return NewInvalidArgumentError(
        absl::StrFormat("plaintext length (%d bytes) exceeds maximum "
                        "allowed (%d bytes)",
                        plaintext_part.size() + plaintext_->size(),
                        kMaxPlaintextBytes),
        CKR_DATA_LEN_RANGE, SOURCE_LOCATION);
  }

  plaintext_->reserve(plaintext_->size() + plaintext_part.size());
  plaintext_->insert(plaintext_->end(), plaintext_part.begin(),
                     plaintext_part.end());

  return absl::OkStatus();
}

absl::StatusOr<absl::Span<const uint8_t>> AesCtrEncrypter::EncryptFinal(
    KmsClient* client) {
  if (!plaintext_) {
    return FailedPreconditionError(
        "EncryptUpdate needs to be called prior to terminating a multi-part "
        "encryption operation",
        CKR_FUNCTION_FAILED, SOURCE_LOCATION);
  }

  kms_v1::RawEncryptRequest req;
  req.set_name(std::string(object_->kms_key_name()));
  req.set_plaintext(std::string(
      reinterpret_cast<const char*>(plaintext_->data()), plaintext_->size()));
  req.set_initialization_vector(
      std::string(reinterpret_cast<const char*>(cb_), sizeof(cb_)));

  ASSIGN_OR_RETURN(kms_v1::RawEncryptResponse resp, client->RawEncrypt(req));

  ciphertext_.resize(resp.ciphertext().size());
  std::copy_n(resp.ciphertext().begin(), resp.ciphertext().size(),
              ciphertext_.begin());

  return absl::MakeConstSpan(ciphertext_);
}

// An implementation of DecrypterInterface that decrypts AES-CTR ciphertexts
// using Cloud KMS.
class AesCtrDecrypter : public DecrypterInterface {
 public:
  static absl::StatusOr<std::unique_ptr<DecrypterInterface>> New(
      std::shared_ptr<Object> key, const CK_MECHANISM* mechanism);

  absl::StatusOr<absl::Span<const uint8_t>> Decrypt(
      KmsClient* client, absl::Span<const uint8_t> ciphertext) override;
  absl::Status DecryptUpdate(
      KmsClient* client, absl::Span<const uint8_t> ciphertext_part) override;
  absl::StatusOr<absl::Span<const uint8_t>> DecryptFinal(
      KmsClient* client) override;

  virtual ~AesCtrDecrypter() {}

 private:
  AesCtrDecrypter(std::shared_ptr<Object> object, CK_BYTE cb[])
      : object_(object) {
    memcpy(cb_, cb, sizeof(cb_));
  }

  std::shared_ptr<Object> object_;
  CK_BYTE cb_[16];
  std::optional<std::vector<uint8_t>> ciphertext_;
  std::vector<uint8_t> plaintext_;
};

absl::StatusOr<std::unique_ptr<DecrypterInterface>> AesCtrDecrypter::New(
    std::shared_ptr<Object> key, const CK_MECHANISM* mechanism) {
  RETURN_IF_ERROR(
      CheckKeyPreconditions(CKK_AES, CKO_SECRET_KEY, CKM_AES_CTR, key.get()));

  ASSIGN_OR_RETURN(
      CK_AES_CTR_PARAMS params,
      ExtractCtrParameters(mechanism->pParameter, mechanism->ulParameterLen));

  return std::unique_ptr<DecrypterInterface>(
      new AesCtrDecrypter(key, params.cb));
}

absl::StatusOr<absl::Span<const uint8_t>> AesCtrDecrypter::Decrypt(
    KmsClient* client, absl::Span<const uint8_t> ciphertext) {
  if (ciphertext.size() > kMaxCiphertextBytes) {
    return NewInvalidArgumentError(
        absl::StrFormat(
            "ciphertext length (%d bytes) exceeds maximum allowed %d",
            ciphertext.size(), kMaxCiphertextBytes),
        CKR_DATA_LEN_RANGE, SOURCE_LOCATION);
  }

  kms_v1::RawDecryptRequest req;
  req.set_name(std::string(object_->kms_key_name()));
  req.set_ciphertext(std::string(
      reinterpret_cast<const char*>(ciphertext.data()), ciphertext.size()));
  req.set_initialization_vector(
      std::string(reinterpret_cast<const char*>(cb_), sizeof(cb_)));

  ASSIGN_OR_RETURN(kms_v1::RawDecryptResponse resp, client->RawDecrypt(req));

  plaintext_.resize(resp.plaintext().size());
  std::copy_n(resp.plaintext().begin(), resp.plaintext().size(),
              plaintext_.begin());

  return absl::MakeConstSpan(plaintext_);
}

absl::Status AesCtrDecrypter::DecryptUpdate(
    KmsClient* client, absl::Span<const uint8_t> ciphertext_part) {
  if (!ciphertext_) {
    ciphertext_.emplace(ciphertext_part.begin(), ciphertext_part.end());
    return absl::OkStatus();
  }

  if (ciphertext_part.size() + ciphertext_->size() > kMaxCiphertextBytes) {
    return NewInvalidArgumentError(
        absl::StrFormat("ciphertext length (%d bytes) exceeds maximum "
                        "allowed (%d bytes)",
                        ciphertext_part.size() + ciphertext_->size(),
                        kMaxCiphertextBytes),
        CKR_DATA_LEN_RANGE, SOURCE_LOCATION);
  }

  ciphertext_->reserve(ciphertext_->size() + ciphertext_part.size());
  ciphertext_->insert(ciphertext_->end(), ciphertext_part.begin(),
                      ciphertext_part.end());

  return absl::OkStatus();
}

absl::StatusOr<absl::Span<const uint8_t>> AesCtrDecrypter::DecryptFinal(
    KmsClient* client) {
  if (!ciphertext_) {
    return FailedPreconditionError(
        "DecryptUpdate needs to be called prior to terminating a multi-part "
        "decryption operation",
        CKR_FUNCTION_FAILED, SOURCE_LOCATION);
  }

  kms_v1::RawDecryptRequest req;
  req.set_name(std::string(object_->kms_key_name()));
  req.set_ciphertext(std::string(
      reinterpret_cast<const char*>(ciphertext_->data()), ciphertext_->size()));
  req.set_initialization_vector(
      std::string(reinterpret_cast<const char*>(cb_), sizeof(cb_)));

  ASSIGN_OR_RETURN(kms_v1::RawDecryptResponse resp, client->RawDecrypt(req));

  plaintext_.resize(resp.plaintext().size());
  std::copy_n(resp.plaintext().begin(), resp.plaintext().size(),
              plaintext_.begin());

  return absl::MakeConstSpan(plaintext_);
}

}  // namespace

absl::StatusOr<std::unique_ptr<EncrypterInterface>> NewAesCtrEncrypter(
    std::shared_ptr<Object> key, const CK_MECHANISM* mechanism) {
  switch (mechanism->mechanism) {
    case CKM_AES_CTR:
      return AesCtrEncrypter::New(key, mechanism);
    default:
      return NewInternalError(
          absl::StrFormat("Mechanism %#x not supported for AES-CTR encryption",
                          mechanism->mechanism),
          SOURCE_LOCATION);
  }
}

absl::StatusOr<std::unique_ptr<DecrypterInterface>> NewAesCtrDecrypter(
    std::shared_ptr<Object> key, const CK_MECHANISM* mechanism) {
  switch (mechanism->mechanism) {
    case CKM_AES_CTR:
      return AesCtrDecrypter::New(key, mechanism);
    default:
      return NewInternalError(
          absl::StrFormat("Mechanism %#x not supported for AES-CTR decryption",
                          mechanism->mechanism),
          SOURCE_LOCATION);
  }
}

}  // namespace kmsp11
