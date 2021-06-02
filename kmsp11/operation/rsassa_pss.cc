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

#include "kmsp11/operation/rsassa_pss.h"

#include "absl/strings/string_view.h"
#include "kmsp11/operation/crypter_interfaces.h"
#include "kmsp11/operation/preconditions.h"
#include "kmsp11/util/crypto_utils.h"
#include "kmsp11/util/errors.h"
#include "kmsp11/util/status_macros.h"

namespace kmsp11 {
namespace {

absl::Status ValidatePssParameters(Object* key, void* parameters,
                                   CK_ULONG parameters_size) {
  if (parameters_size != sizeof(CK_RSA_PKCS_PSS_PARAMS)) {
    return InvalidMechanismParamError(
        "mechanism parameters must be of type CK_RSA_PKCS_PSS_PARAMS",
        SOURCE_LOCATION);
  }
  CK_RSA_PKCS_PSS_PARAMS* params = (CK_RSA_PKCS_PSS_PARAMS*)parameters;

  ASSIGN_OR_RETURN(const EVP_MD* digest,
                   DigestForMechanism(*key->algorithm().digest_mechanism));
  RETURN_IF_ERROR(EnsureHashMatches(params->hashAlg, digest));
  RETURN_IF_ERROR(EnsureMgf1HashMatches(params->mgf, digest));

  size_t expected_salt_length = EVP_MD_size(digest);
  if (params->sLen != expected_salt_length) {
    return InvalidMechanismParamError(
        absl::StrFormat("expected salt length for key %s is %d, but %d "
                        "was supplied in the parameters",
                        key->kms_key_name(), expected_salt_length,
                        params->sLen),
        SOURCE_LOCATION);
  }

  return absl::OkStatus();
}

}  // namespace

absl::StatusOr<std::unique_ptr<SignerInterface>> RsaPssSigner::New(
    std::shared_ptr<Object> key, const CK_MECHANISM* mechanism) {
  RETURN_IF_ERROR(CheckKeyPreconditions(CKK_RSA, CKO_PRIVATE_KEY,
                                        CKM_RSA_PKCS_PSS, key.get()));
  RETURN_IF_ERROR(ValidatePssParameters(key.get(), mechanism->pParameter,
                                        mechanism->ulParameterLen));

  ASSIGN_OR_RETURN(absl::string_view key_der,
                   key->attributes().Value(CKA_PUBLIC_KEY_INFO));
  ASSIGN_OR_RETURN(bssl::UniquePtr<EVP_PKEY> parsed_key,
                   ParseX509PublicKeyDer(key_der));

  return std::unique_ptr<SignerInterface>(
      new RsaPssSigner(key, std::move(parsed_key)));
}

size_t RsaPssSigner::signature_length() {
  return RSA_size(EVP_PKEY_get0_RSA(key_.get()));
}

absl::StatusOr<std::unique_ptr<VerifierInterface>> RsaPssVerifier::New(
    std::shared_ptr<Object> key, const CK_MECHANISM* mechanism) {
  RETURN_IF_ERROR(CheckKeyPreconditions(CKK_RSA, CKO_PUBLIC_KEY,
                                        CKM_RSA_PKCS_PSS, key.get()));
  RETURN_IF_ERROR(ValidatePssParameters(key.get(), mechanism->pParameter,
                                        mechanism->ulParameterLen));

  ASSIGN_OR_RETURN(absl::string_view key_der,
                   key->attributes().Value(CKA_PUBLIC_KEY_INFO));
  ASSIGN_OR_RETURN(bssl::UniquePtr<EVP_PKEY> parsed_key,
                   ParseX509PublicKeyDer(key_der));

  return std::unique_ptr<VerifierInterface>(
      new RsaPssVerifier(key, std::move(parsed_key)));
}

absl::Status RsaPssVerifier::Verify(KmsClient* client,
                                    absl::Span<const uint8_t> digest,
                                    absl::Span<const uint8_t> signature) {
  ASSIGN_OR_RETURN(const EVP_MD* md,
                   DigestForMechanism(*object_->algorithm().digest_mechanism));
  return RsaVerifyPss(key_.get(), md, digest, signature);
}

}  // namespace kmsp11
