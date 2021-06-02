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

#include "kmsp11/operation/ecdsa.h"

#include "absl/strings/string_view.h"
#include "kmsp11/operation/crypter_interfaces.h"
#include "kmsp11/operation/preconditions.h"
#include "kmsp11/util/crypto_utils.h"
#include "kmsp11/util/errors.h"
#include "kmsp11/util/status_macros.h"

namespace kmsp11 {

absl::StatusOr<std::unique_ptr<SignerInterface>> EcdsaSigner::New(
    std::shared_ptr<Object> key, const CK_MECHANISM* mechanism) {
  RETURN_IF_ERROR(
      CheckKeyPreconditions(CKK_EC, CKO_PRIVATE_KEY, CKM_ECDSA, key.get()));
  RETURN_IF_ERROR(EnsureNoParameters(mechanism));

  ASSIGN_OR_RETURN(absl::string_view key_der,
                   key->attributes().Value(CKA_PUBLIC_KEY_INFO));
  ASSIGN_OR_RETURN(bssl::UniquePtr<EVP_PKEY> parsed_key,
                   ParseX509PublicKeyDer(key_der));

  return std::unique_ptr<SignerInterface>(new EcdsaSigner(
      key, bssl::UniquePtr<EC_KEY>(EVP_PKEY_get1_EC_KEY(parsed_key.get()))));
}

size_t EcdsaSigner::signature_length() {
  return EcdsaSigLengthP1363(EC_KEY_get0_group(key_.get()));
}

absl::Status EcdsaSigner::CopySignature(absl::string_view src,
                                        absl::Span<uint8_t> dest) {
  ASSIGN_OR_RETURN(std::vector<uint8_t> p1363_sig,
                   EcdsaSigAsn1ToP1363(src, EC_KEY_get0_group(key_.get())));
  if (p1363_sig.size() != signature_length()) {
    return NewInternalError(
        absl::StrFormat("unexpected signature length (got %d, want %d)",
                        p1363_sig.size(), signature_length()),
        SOURCE_LOCATION);
  }
  std::copy(p1363_sig.begin(), p1363_sig.end(), dest.data());
  return absl::OkStatus();
}

absl::StatusOr<std::unique_ptr<VerifierInterface>> EcdsaVerifier::New(
    std::shared_ptr<Object> key, const CK_MECHANISM* mechanism) {
  RETURN_IF_ERROR(
      CheckKeyPreconditions(CKK_EC, CKO_PUBLIC_KEY, CKM_ECDSA, key.get()));
  RETURN_IF_ERROR(EnsureNoParameters(mechanism));

  ASSIGN_OR_RETURN(absl::string_view key_der,
                   key->attributes().Value(CKA_PUBLIC_KEY_INFO));
  ASSIGN_OR_RETURN(bssl::UniquePtr<EVP_PKEY> parsed_key,
                   ParseX509PublicKeyDer(key_der));

  return std::unique_ptr<VerifierInterface>(new EcdsaVerifier(
      key, bssl::UniquePtr<EC_KEY>(EVP_PKEY_get1_EC_KEY(parsed_key.get()))));
}

absl::Status EcdsaVerifier::Verify(KmsClient* client,
                                   absl::Span<const uint8_t> digest,
                                   absl::Span<const uint8_t> signature) {
  ASSIGN_OR_RETURN(const EVP_MD* md,
                   DigestForMechanism(*object_->algorithm().digest_mechanism));
  return EcdsaVerifyP1363(key_.get(), md, digest, signature);
}

}  // namespace kmsp11
