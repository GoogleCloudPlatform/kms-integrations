#include "kmsp11/operation/rsassa_raw_pkcs1.h"

#include "absl/strings/string_view.h"
#include "kmsp11/operation/crypter_interfaces.h"
#include "kmsp11/operation/preconditions.h"
#include "kmsp11/util/crypto_utils.h"
#include "kmsp11/util/errors.h"
#include "kmsp11/util/status_macros.h"
#include "openssl/x509.h"

namespace kmsp11 {

absl::StatusOr<std::unique_ptr<SignerInterface>> RsaRawPkcs1Signer::New(
    std::shared_ptr<Object> key, const CK_MECHANISM* mechanism) {
  RETURN_IF_ERROR(
      CheckKeyPreconditions(CKK_RSA, CKO_PRIVATE_KEY, CKM_RSA_PKCS, key.get()));
  RETURN_IF_ERROR(EnsureNoParameters(mechanism));

  ASSIGN_OR_RETURN(absl::string_view key_der,
                   key->attributes().Value(CKA_PUBLIC_KEY_INFO));
  ASSIGN_OR_RETURN(bssl::UniquePtr<EVP_PKEY> parsed_key,
                   ParseX509PublicKeyDer(key_der));

  return std::unique_ptr<SignerInterface>(new RsaRawPkcs1Signer(
      key, bssl::UniquePtr<RSA>(EVP_PKEY_get1_RSA(parsed_key.get()))));
}

size_t RsaRawPkcs1Signer::signature_length() { return RSA_size(key_.get()); }

absl::Status RsaRawPkcs1Signer::Sign(KmsClient* client,
                                     absl::Span<const uint8_t> data,
                                     absl::Span<uint8_t> signature) {
  constexpr size_t kRsaPkcs1OverheadBytes = 11;
  if (data.size() + kRsaPkcs1OverheadBytes > RSA_size(key_.get())) {
    // TODO(bdhess): better error message
    return NewInvalidArgumentError("data is too large", CKR_DATA_LEN_RANGE,
                                   SOURCE_LOCATION);
  }

  if (signature.size() != signature_length()) {
    return NewInternalError(
        absl::StrFormat(
            "provided signature buffer has incorrect size (got %d, want %d)",
            signature.size(), signature_length()),
        SOURCE_LOCATION);
  }

  kms_v1::AsymmetricSignRequest req;
  req.set_name(std::string(object_->kms_key_name()));
  req.set_data(
      std::string(reinterpret_cast<const char*>(data.data()), data.size()));

  ASSIGN_OR_RETURN(kms_v1::AsymmetricSignResponse resp,
                   client->AsymmetricSign(req));
  std::copy(resp.signature().begin(), resp.signature().end(),
            signature.begin());
  return absl::OkStatus();
}

absl::StatusOr<std::unique_ptr<VerifierInterface>> RsaRawPkcs1Verifier::New(
    std::shared_ptr<Object> key, const CK_MECHANISM* mechanism) {
  RETURN_IF_ERROR(
      CheckKeyPreconditions(CKK_RSA, CKO_PUBLIC_KEY, CKM_RSA_PKCS, key.get()));
  RETURN_IF_ERROR(EnsureNoParameters(mechanism));

  ASSIGN_OR_RETURN(absl::string_view key_der,
                   key->attributes().Value(CKA_PUBLIC_KEY_INFO));
  ASSIGN_OR_RETURN(bssl::UniquePtr<EVP_PKEY> parsed_key,
                   ParseX509PublicKeyDer(key_der));

  return std::unique_ptr<VerifierInterface>(new RsaRawPkcs1Verifier(
      bssl::UniquePtr<RSA>(EVP_PKEY_get1_RSA(parsed_key.get()))));
}

absl::Status RsaRawPkcs1Verifier::Verify(KmsClient* client,
                                         absl::Span<const uint8_t> data,
                                         absl::Span<const uint8_t> signature) {
  return RsaVerifyRawPkcs1(key_.get(), data, signature);
}

}  // namespace kmsp11
