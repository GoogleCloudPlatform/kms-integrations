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

#include "kmsp11/operation/rsassa_pkcs1.h"

#include <string_view>

#include "kmsp11/operation/crypter_interfaces.h"
#include "kmsp11/operation/preconditions.h"
#include "kmsp11/util/crypto_utils.h"
#include "kmsp11/util/errors.h"
#include "kmsp11/util/status_macros.h"

namespace kmsp11 {

namespace {

absl::StatusOr<std::vector<uint8_t>> ExtractDigest(
    absl::Span<const uint8_t> digest_info_der, int expected_digest_nid) {
  const uint8_t* data = digest_info_der.data();

  bssl::UniquePtr<X509_SIG> digest_info(
      d2i_X509_SIG(nullptr, &data, digest_info_der.size()));
  if (!digest_info) {
    return NewInvalidArgumentError(
        absl::StrCat("error parsing DigestInfo: ", SslErrorToString()),
        CKR_DATA_INVALID, SOURCE_LOCATION);
  }

  const X509_ALGOR* algorithm;
  const ASN1_OCTET_STRING* digest;
  X509_SIG_get0(digest_info.get(), &algorithm, &digest);

  int got_nid = OBJ_obj2nid(algorithm->algorithm);
  if (got_nid != expected_digest_nid) {
    return NewInvalidArgumentError(
        absl::StrFormat("digest algorithm NID mismatch (got %d, want %d)",
                        got_nid, expected_digest_nid),
        CKR_DATA_INVALID, SOURCE_LOCATION);
  }

  return std::vector<uint8_t>(digest->data, digest->data + digest->length);
}

}  // namespace

absl::StatusOr<std::unique_ptr<SignerInterface>> RsaPkcs1Signer::New(
    std::shared_ptr<Object> key, const CK_MECHANISM* mechanism) {
  RETURN_IF_ERROR(
      CheckKeyPreconditions(CKK_RSA, CKO_PRIVATE_KEY, CKM_RSA_PKCS, key.get()));
  RETURN_IF_ERROR(EnsureNoParameters(mechanism));

  ASSIGN_OR_RETURN(std::string_view key_der,
                   key->attributes().Value(CKA_PUBLIC_KEY_INFO));
  ASSIGN_OR_RETURN(bssl::UniquePtr<EVP_PKEY> parsed_key,
                   ParseX509PublicKeyDer(key_der));

  return std::unique_ptr<SignerInterface>(new RsaPkcs1Signer(
      key, bssl::UniquePtr<RSA>(EVP_PKEY_get1_RSA(parsed_key.get()))));
}

size_t RsaPkcs1Signer::signature_length() { return RSA_size(key_.get()); }

absl::Status RsaPkcs1Signer::Sign(KmsClient* client,
                                  absl::Span<const uint8_t> data,
                                  absl::Span<uint8_t> signature) {
  ASSIGN_OR_RETURN(const EVP_MD* md,
                   DigestForMechanism(*object()->algorithm().digest_mechanism));
  ASSIGN_OR_RETURN(std::vector<uint8_t> digest,
                   ExtractDigest(data, EVP_MD_type(md)));
  return KmsDigestSigner::Sign(client, digest, signature);
}

absl::StatusOr<std::unique_ptr<VerifierInterface>> RsaPkcs1Verifier::New(
    std::shared_ptr<Object> key, const CK_MECHANISM* mechanism) {
  RETURN_IF_ERROR(
      CheckKeyPreconditions(CKK_RSA, CKO_PUBLIC_KEY, CKM_RSA_PKCS, key.get()));
  RETURN_IF_ERROR(EnsureNoParameters(mechanism));

  ASSIGN_OR_RETURN(std::string_view key_der,
                   key->attributes().Value(CKA_PUBLIC_KEY_INFO));
  ASSIGN_OR_RETURN(bssl::UniquePtr<EVP_PKEY> parsed_key,
                   ParseX509PublicKeyDer(key_der));

  return std::unique_ptr<VerifierInterface>(new RsaPkcs1Verifier(
      key, bssl::UniquePtr<RSA>(EVP_PKEY_get1_RSA(parsed_key.get()))));
}

absl::Status RsaPkcs1Verifier::Verify(KmsClient* client,
                                      absl::Span<const uint8_t> data,
                                      absl::Span<const uint8_t> signature) {
  ASSIGN_OR_RETURN(const EVP_MD* md,
                   DigestForMechanism(*object_->algorithm().digest_mechanism));
  ASSIGN_OR_RETURN(std::vector<uint8_t> digest,
                   ExtractDigest(data, EVP_MD_type(md)));
  return RsaVerifyPkcs1(key_.get(), md, digest, signature);
}

}  // namespace kmsp11
