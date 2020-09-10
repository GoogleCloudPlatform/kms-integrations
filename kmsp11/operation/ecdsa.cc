#include "kmsp11/operation/ecdsa.h"

#include "absl/strings/string_view.h"
#include "kmsp11/operation/crypter_interfaces.h"
#include "kmsp11/operation/preconditions.h"
#include "kmsp11/util/crypto_utils.h"
#include "kmsp11/util/errors.h"
#include "kmsp11/util/status_macros.h"
#include "openssl/ec_key.h"

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
  return EcdsaVerifyP1363(key_.get(), object_->algorithm().digest, digest,
                          signature);
}

}  // namespace kmsp11
