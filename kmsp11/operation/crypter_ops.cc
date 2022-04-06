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

#include "kmsp11/operation/crypter_ops.h"

#include "kmsp11/operation/ecdsa.h"
#include "kmsp11/operation/kms_digesting_signer.h"
#include "kmsp11/operation/kms_digesting_verifier.h"
#include "kmsp11/operation/rsaes_oaep.h"
#include "kmsp11/operation/rsassa_pkcs1.h"
#include "kmsp11/operation/rsassa_pss.h"
#include "kmsp11/operation/rsassa_raw_pkcs1.h"
#include "kmsp11/util/errors.h"

namespace kmsp11 {

absl::StatusOr<DecryptOp> NewDecryptOp(std::shared_ptr<Object> key,
                                       const CK_MECHANISM* mechanism) {
  switch (mechanism->mechanism) {
    case CKM_RSA_PKCS_OAEP:
      return RsaOaepDecrypter::New(key, mechanism);
    default:
      return InvalidMechanismError(mechanism->mechanism, "decrypt",
                                   SOURCE_LOCATION);
  }
}

absl::StatusOr<EncryptOp> NewEncryptOp(std::shared_ptr<Object> key,
                                       const CK_MECHANISM* mechanism) {
  switch (mechanism->mechanism) {
    case CKM_RSA_PKCS_OAEP:
      return RsaOaepEncrypter::New(key, mechanism);
    default:
      return InvalidMechanismError(mechanism->mechanism, "encrypt",
                                   SOURCE_LOCATION);
  }
}

absl::StatusOr<SignOp> NewSignOp(std::shared_ptr<Object> key,
                                 const CK_MECHANISM* mechanism) {
  switch (mechanism->mechanism) {
    case CKM_ECDSA:
    case CKM_ECDSA_SHA256:
    case CKM_ECDSA_SHA384:
      return NewEcdsaSigner(key, mechanism);
    case CKM_RSA_PKCS:
      if (!key->algorithm().digest_mechanism.has_value()) {
        return RsaRawPkcs1Signer::New(key, mechanism);
      }
      return RsaPkcs1Signer::New(key, mechanism);
    case CKM_RSA_PKCS_PSS:
    case CKM_SHA256_RSA_PKCS_PSS:
    case CKM_SHA512_RSA_PKCS_PSS:
      return NewRsaPssSigner(key, mechanism);
    case CKM_SHA256_RSA_PKCS:
    case CKM_SHA512_RSA_PKCS:
      return KmsDigestingSigner::New(key, mechanism);
    default:
      return InvalidMechanismError(mechanism->mechanism, "sign",
                                   SOURCE_LOCATION);
  }
}

absl::StatusOr<VerifyOp> NewVerifyOp(std::shared_ptr<Object> key,
                                     const CK_MECHANISM* mechanism) {
  switch (mechanism->mechanism) {
    case CKM_ECDSA:
    case CKM_ECDSA_SHA256:
    case CKM_ECDSA_SHA384:
      return NewEcdsaVerifier(key, mechanism);
    case CKM_RSA_PKCS:
      if (!key->algorithm().digest_mechanism.has_value()) {
        return RsaRawPkcs1Verifier::New(key, mechanism);
      }
      return RsaPkcs1Verifier::New(key, mechanism);
    case CKM_RSA_PKCS_PSS:
    case CKM_SHA256_RSA_PKCS_PSS:
    case CKM_SHA512_RSA_PKCS_PSS:
      return NewRsaPssVerifier(key, mechanism);
    case CKM_SHA256_RSA_PKCS:
    case CKM_SHA512_RSA_PKCS:
      return KmsDigestingVerifier::New(key, mechanism);
    default:
      return InvalidMechanismError(mechanism->mechanism, "verify",
                                   SOURCE_LOCATION);
  }
}

}  // namespace kmsp11
