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

#include "kmsp11/operation/aes_gcm.h"

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
constexpr size_t kMaxCiphertextBytes = 10 * kMaxPlaintextBytes;

absl::StatusOr<CK_GCM_PARAMS> ExtractGcmParameters(void* parameters,
                                                   CK_ULONG parameters_size) {
  CK_GCM_PARAMS params;
  switch (parameters_size) {
    case sizeof(CK_GCM_PARAMS):
      params = *reinterpret_cast<CK_GCM_PARAMS*>(parameters);
      break;

    case sizeof(CK_GCM_PARAMS_errata): {
      CK_GCM_PARAMS_errata* params_errata =
          reinterpret_cast<CK_GCM_PARAMS_errata*>(parameters);

      params.pIv = params_errata->pIv;
      params.ulIvLen = params_errata->ulIvLen;
      params.ulIvBits = params_errata->ulIvLen * 8;
      params.pAAD = params_errata->pAAD;
      params.ulAADLen = params_errata->ulAADLen;
      params.ulTagBits = params_errata->ulTagBits;
      break;
    }
    default:
      return InvalidMechanismParamError(
          "mechanism parameters must be of type CK_GCM_PARAMS",
          SOURCE_LOCATION);
  }

  if (!params.pIv) {
    return InvalidMechanismParamError(
        "missing pIv param, which should point to a zero-initialized 12-byte "
        "buffer",
        SOURCE_LOCATION);
  }
  if (params.ulIvLen != 12 || params.ulIvBits != 96) {
    return InvalidMechanismParamError(
        "the only supported IV length is the default 12 bytes",
        SOURCE_LOCATION);
  }
  if (params.ulAADLen != 0 && !params.pAAD) {
    return InvalidMechanismParamError(
        "AAD length specified but the AAD pointer is invalid", SOURCE_LOCATION);
  }
  if (params.ulTagBits != 128) {
    return InvalidMechanismParamError(
        "the only supported tag length is the default 128 bits",
        SOURCE_LOCATION);
  }

  return params;
}

// An implementation of EncrypterInterface that encrypts AES-GCM ciphertexts
// using Cloud KMS.
class AesGcmEncrypter : public EncrypterInterface {
 public:
  static absl::StatusOr<std::unique_ptr<EncrypterInterface>> New(
      std::shared_ptr<Object> key, const CK_MECHANISM* mechanism);

  absl::StatusOr<absl::Span<const uint8_t>> Encrypt(
      KmsClient* client, absl::Span<const uint8_t> ciphertext) override;

  virtual ~AesGcmEncrypter() {}

 private:
  AesGcmEncrypter(std::shared_ptr<Object> object, absl::Span<const uint8_t> aad,
                  absl::Span<uint8_t> iv)
      : object_(object), iv_(iv) {
    if (!aad.empty() && aad.data()) {
      aad_.emplace(aad.begin(), aad.end());
    }
  }

  std::shared_ptr<Object> object_;
  std::optional<std::vector<uint8_t>> aad_;
  absl::Span<uint8_t> iv_;
  std::vector<uint8_t> ciphertext_;
};

absl::StatusOr<std::unique_ptr<EncrypterInterface>> AesGcmEncrypter::New(
    std::shared_ptr<Object> key, const CK_MECHANISM* mechanism) {
  RETURN_IF_ERROR(CheckKeyPreconditions(CKK_AES, CKO_SECRET_KEY,
                                        CKM_CLOUDKMS_AES_GCM, key.get()));

  ASSIGN_OR_RETURN(
      CK_GCM_PARAMS params,
      ExtractGcmParameters(mechanism->pParameter, mechanism->ulParameterLen));

  // For encryption only, pIv should be zero-initialized.
  if (params.pIv[0] != '\0' || memcmp(params.pIv, params.pIv + 1, 11) != 0) {
    return InvalidMechanismParamError(
        "the pIv param should point to a zero-initialized 12-byte buffer",
        SOURCE_LOCATION);
  }

  return std::unique_ptr<EncrypterInterface>(new AesGcmEncrypter(
      key, absl::MakeConstSpan(params.pAAD, params.ulAADLen),
      absl::MakeSpan(params.pIv, params.ulIvLen)));
}

absl::StatusOr<absl::Span<const uint8_t>> AesGcmEncrypter::Encrypt(
    KmsClient* client, absl::Span<const uint8_t> plaintext) {
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
  if (aad_ && !aad_->empty()) {
    req.set_additional_authenticated_data(
        std::string(reinterpret_cast<const char*>(aad_->data()), aad_->size()));
  }

  ASSIGN_OR_RETURN(kms_v1::RawEncryptResponse resp, client->RawEncrypt(req));

  std::copy_n(resp.initialization_vector().begin(), resp.initialization_vector().size(), iv_.begin());

  ciphertext_.resize(resp.ciphertext().size());
  std::copy_n(resp.ciphertext().begin(), resp.ciphertext().size(), ciphertext_.begin());

  return absl::MakeConstSpan(ciphertext_);
}

// An implementation of DecrypterInterface that decrypts AES-GCM ciphertexts
// using Cloud KMS.
class AesGcmDecrypter : public DecrypterInterface {
 public:
  static absl::StatusOr<std::unique_ptr<DecrypterInterface>> New(
      std::shared_ptr<Object> key, const CK_MECHANISM* mechanism);

  absl::StatusOr<absl::Span<const uint8_t>> Decrypt(
      KmsClient* client, absl::Span<const uint8_t> plaintext) override;

  virtual ~AesGcmDecrypter() {}

 private:
  AesGcmDecrypter(std::shared_ptr<Object> object, absl::Span<const uint8_t> aad,
                  absl::Span<const uint8_t> iv)
      : object_(object), iv_(iv.begin(), iv.end()) {
    if (!aad.empty()) {
      aad_.emplace(aad.begin(), aad.end());
    }
  }

  std::shared_ptr<Object> object_;
  std::optional<std::vector<uint8_t>> aad_;
  std::vector<uint8_t> iv_;
  std::vector<uint8_t> plaintext_;
};

absl::StatusOr<std::unique_ptr<DecrypterInterface>> AesGcmDecrypter::New(
    std::shared_ptr<Object> key, const CK_MECHANISM* mechanism) {
  RETURN_IF_ERROR(CheckKeyPreconditions(CKK_AES, CKO_SECRET_KEY,
                                        CKM_CLOUDKMS_AES_GCM, key.get()));

  ASSIGN_OR_RETURN(
      CK_GCM_PARAMS params,
      ExtractGcmParameters(mechanism->pParameter, mechanism->ulParameterLen));

  return std::unique_ptr<DecrypterInterface>(new AesGcmDecrypter(
      key, absl::MakeConstSpan(params.pAAD, params.ulAADLen),
      absl::MakeConstSpan(params.pIv, params.ulIvLen)));
}

absl::StatusOr<absl::Span<const uint8_t>> AesGcmDecrypter::Decrypt(
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
      std::string(reinterpret_cast<const char*>(iv_.data()), iv_.size()));
  if (aad_ && !aad_->empty()) {
    req.set_additional_authenticated_data(
        std::string(reinterpret_cast<const char*>(aad_->data()), aad_->size()));
  }

  ASSIGN_OR_RETURN(kms_v1::RawDecryptResponse resp, client->RawDecrypt(req));

  plaintext_.resize(resp.plaintext().size());
  std::copy_n(resp.plaintext().begin(), resp.plaintext().size(),
              plaintext_.begin());

  return absl::MakeConstSpan(plaintext_);
}

}  // namespace

absl::StatusOr<std::unique_ptr<EncrypterInterface>> NewAesGcmEncrypter(
    std::shared_ptr<Object> key, const CK_MECHANISM* mechanism) {
  switch (mechanism->mechanism) {
    case CKM_CLOUDKMS_AES_GCM:
      return AesGcmEncrypter::New(key, mechanism);
    default:
      return NewInternalError(
          absl::StrFormat("Mechanism %#x not supported for AES encryption",
                          mechanism->mechanism),
          SOURCE_LOCATION);
  }
}

absl::StatusOr<std::unique_ptr<DecrypterInterface>> NewAesGcmDecrypter(
    std::shared_ptr<Object> key, const CK_MECHANISM* mechanism) {
  switch (mechanism->mechanism) {
    case CKM_CLOUDKMS_AES_GCM:
      return AesGcmDecrypter::New(key, mechanism);
    default:
      return NewInternalError(
          absl::StrFormat("Mechanism %#x not supported for AES decryption",
                          mechanism->mechanism),
          SOURCE_LOCATION);
  }
}

}  // namespace kmsp11
