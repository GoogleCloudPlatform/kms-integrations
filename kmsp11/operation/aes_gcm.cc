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

// The PKCS#11 v2.40 Errata 01 specification defines CK_GCM_PARAMS in chapter
// 2.12.3 without a ulIvBits member, but the PKCS#11 v2.40 Errata 01 headers
// define CK_GCM_PARAMS with ulIvBits. We support both, for compatibility. See
// https://github.com/Pkcs11Interop/Pkcs11Interop/issues/126#issuecomment-496687863
// for a more detailed explanation.
typedef struct CK_GCM_PARAMS_errata {
  CK_BYTE_PTR pIv;
  CK_ULONG ulIvLen;
  CK_BYTE_PTR pAAD;
  CK_ULONG ulAADLen;
  CK_ULONG ulTagBits;
} CK_GCM_PARAMS_errata;

constexpr size_t kMaxPlaintextBytes = 64 * 1024;

absl::Status ValidateAesGcmParameters(Object* key, void* parameters,
                                      CK_ULONG parameters_size) {
  if (parameters_size != sizeof(CK_GCM_PARAMS) &&
      parameters_size != sizeof(CK_GCM_PARAMS_errata)) {
    return InvalidMechanismParamError(
        "mechanism parameters must be of type CK_GCM_PARAMS", SOURCE_LOCATION);
  }

  if (parameters_size == sizeof(CK_GCM_PARAMS)) {
    CK_GCM_PARAMS* params = reinterpret_cast<CK_GCM_PARAMS*>(parameters);

    if (!params->pIv) {
      return InvalidMechanismParamError(
          "missing pIv param, which should point to a zero-initialized 12-byte "
          "buffer",
          SOURCE_LOCATION);
    }
    if (params->ulIvLen != 12 || params->ulIvBits != 96) {
      return InvalidMechanismParamError(
          "the only supported IV length is the default 12 bytes",
          SOURCE_LOCATION);
    }
    if (params->ulTagBits != 128) {
      return InvalidMechanismParamError(
          "the only supported tag length is the default 128 bits",
          SOURCE_LOCATION);
    }
  } else {
    CK_GCM_PARAMS_errata* params =
        reinterpret_cast<CK_GCM_PARAMS_errata*>(parameters);

    if (!params->pIv) {
      return InvalidMechanismParamError(
          "missing pIv param, which should point to a zero-initialized 12-byte "
          "buffer",
          SOURCE_LOCATION);
    }
    if (params->ulIvLen != 12) {
      return InvalidMechanismParamError(
          "the only supported IV length is the default 12 bytes",
          SOURCE_LOCATION);
    }
    if (params->ulTagBits != 128) {
      return InvalidMechanismParamError(
          "the only supported tag length is the default 128 bits",
          SOURCE_LOCATION);
    }
  }

  return absl::OkStatus();
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
    aad_.emplace(aad.begin(), aad.end());
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
  RETURN_IF_ERROR(ValidateAesGcmParameters(key.get(), mechanism->pParameter,
                                           mechanism->ulParameterLen));

  if (mechanism->ulParameterLen == sizeof(CK_GCM_PARAMS)) {
    CK_GCM_PARAMS* params =
        reinterpret_cast<CK_GCM_PARAMS*>(mechanism->pParameter);

    // For encryption only, pIv should be zero-initialized.
    if (params->pIv[0] != '\0' ||
        memcmp(params->pIv, params->pIv + 1, 11) != 0) {
      return InvalidMechanismParamError(
          "the pIv param should point to a zero-initialized 12-byte buffer",
          SOURCE_LOCATION);
    }

    return std::unique_ptr<EncrypterInterface>(new AesGcmEncrypter(
        key, absl::MakeConstSpan(params->pAAD, params->ulAADLen),
        absl::MakeSpan(params->pIv, params->ulIvLen)));
  }

  CK_GCM_PARAMS_errata* params =
      reinterpret_cast<CK_GCM_PARAMS_errata*>(mechanism->pParameter);

  // For encryption only, pIv should be zero-initialized.
  if (params->pIv[0] != '\0' || memcmp(params->pIv, params->pIv + 1, 11) != 0) {
    return InvalidMechanismParamError(
        "the pIv param should point to a zero-initialized 12-byte buffer",
        SOURCE_LOCATION);
  }

  return std::unique_ptr<EncrypterInterface>(new AesGcmEncrypter(
      key, absl::MakeConstSpan(params->pAAD, params->ulAADLen),
      absl::MakeSpan(params->pIv, params->ulIvLen)));
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

}  // namespace

absl::StatusOr<std::unique_ptr<EncrypterInterface>> NewAesGcmEncrypter(
    std::shared_ptr<Object> key, const CK_MECHANISM* mechanism) {
  switch (mechanism->mechanism) {
    case CKM_CLOUDKMS_AES_GCM:
      return AesGcmEncrypter::New(key, mechanism);
    case CKM_AES_GCM:
      return NewInternalError(
          absl::StrFormat(
              "Mechanism %#x not supported for AES-GCM encryption, the"
              "Cloud KMS PKCS #11 library defines a custom mechanism"
              "(CKM_CLOUDKMS_AES_GCM) that you can use instead",
              mechanism->mechanism),
          SOURCE_LOCATION);
    default:
      return NewInternalError(
          absl::StrFormat("Mechanism %#x not supported for AES encryption",
                          mechanism->mechanism),
          SOURCE_LOCATION);
  }
}

}  // namespace kmsp11
