#include "kmsp11/operation/rsaes_oaep.h"

#include "absl/cleanup/cleanup.h"
#include "kmsp11/object.h"
#include "kmsp11/operation/preconditions.h"
#include "kmsp11/util/crypto_utils.h"
#include "kmsp11/util/errors.h"
#include "kmsp11/util/status_macros.h"
#include "kmsp11/util/string_utils.h"

namespace kmsp11 {

namespace {

absl::Status ValidateRsaOaepParameters(Object* key, void* parameters,
                                       CK_ULONG parameters_size) {
  if (parameters_size != sizeof(CK_RSA_PKCS_OAEP_PARAMS)) {
    return InvalidMechanismParamError(
        "mechanism parameters must be of type CK_RSA_PKCS_OAEP_PARAMS",
        SOURCE_LOCATION);
  }
  CK_RSA_PKCS_OAEP_PARAMS* params = (CK_RSA_PKCS_OAEP_PARAMS*)parameters;

  ASSIGN_OR_RETURN(const EVP_MD* digest,
                   DigestForMechanism(*key->algorithm().digest_mechanism));
  RETURN_IF_ERROR(EnsureHashMatches(params->hashAlg, digest));
  RETURN_IF_ERROR(EnsureMgf1HashMatches(params->mgf, digest));

  if (params->source != CKZ_DATA_SPECIFIED) {
    return InvalidMechanismParamError(
        "source for OAEP must be CKZ_DATA_SPECIFIED", SOURCE_LOCATION);
  }
  if (params->pSourceData != nullptr || params->ulSourceDataLen != 0) {
    return InvalidMechanismParamError("OAEP labels are not supported",
                                      SOURCE_LOCATION);
  }

  return absl::OkStatus();
}

}  // namespace

absl::StatusOr<std::unique_ptr<EncrypterInterface>> RsaOaepEncrypter::New(
    std::shared_ptr<Object> key, const CK_MECHANISM* mechanism) {
  RETURN_IF_ERROR(CheckKeyPreconditions(CKK_RSA, CKO_PUBLIC_KEY,
                                        CKM_RSA_PKCS_OAEP, key.get()));
  RETURN_IF_ERROR(ValidateRsaOaepParameters(key.get(), mechanism->pParameter,
                                            mechanism->ulParameterLen));

  ASSIGN_OR_RETURN(absl::string_view key_der,
                   key->attributes().Value(CKA_PUBLIC_KEY_INFO));
  ASSIGN_OR_RETURN(bssl::UniquePtr<EVP_PKEY> parsed_key,
                   ParseX509PublicKeyDer(key_der));

  return std::unique_ptr<EncrypterInterface>(
      new RsaOaepEncrypter(key, std::move(parsed_key)));
}

absl::StatusOr<absl::Span<const uint8_t>> RsaOaepEncrypter::Encrypt(
    KmsClient* client, absl::Span<const uint8_t> plaintext) {
  ASSIGN_OR_RETURN(const EVP_MD* digest,
                   DigestForMechanism(*object_->algorithm().digest_mechanism));
  RETURN_IF_ERROR(EncryptRsaOaep(key_.get(), digest, plaintext,
                                 absl::MakeSpan(ciphertext_)));
  return absl::MakeConstSpan(ciphertext_);
}

absl::StatusOr<std::unique_ptr<DecrypterInterface>> RsaOaepDecrypter::New(
    std::shared_ptr<Object> key, const CK_MECHANISM* mechanism) {
  RETURN_IF_ERROR(CheckKeyPreconditions(CKK_RSA, CKO_PRIVATE_KEY,
                                        CKM_RSA_PKCS_OAEP, key.get()));
  RETURN_IF_ERROR(ValidateRsaOaepParameters(key.get(), mechanism->pParameter,
                                            mechanism->ulParameterLen));
  return std::unique_ptr<DecrypterInterface>(new RsaOaepDecrypter(key));
}

absl::StatusOr<absl::Span<const uint8_t>> RsaOaepDecrypter::Decrypt(
    KmsClient* client, absl::Span<const uint8_t> ciphertext) {
  if (result_ && result_->Matches(ciphertext)) {
    return result_->plaintext();
  }

  size_t expected_size = key_->algorithm().key_bit_length / 8;
  if (ciphertext.size() != expected_size) {
    return NewInvalidArgumentError(
        absl::StrFormat("ciphertext size mismatch (got %d, want %d)",
                        ciphertext.size(), expected_size),
        CKR_ENCRYPTED_DATA_LEN_RANGE, SOURCE_LOCATION);
  }

  kms_v1::AsymmetricDecryptRequest req;
  req.set_name(std::string(key_->kms_key_name()));
  req.set_ciphertext(ciphertext.data(), ciphertext.size());
  absl::Cleanup c = [&] { ZeroDelete()(req.release_ciphertext()); };

  absl::StatusOr<kms_v1::AsymmetricDecryptResponse> resp_or =
      client->AsymmetricDecrypt(req);
  if (!resp_or.ok()) {
    switch (resp_or.status().code()) {
      case absl::StatusCode::kInvalidArgument:
        // TODO(bdhess): Consider if there is a clearer way for KMS to specify
        // that it's the ciphertext that's invalid (and not something else).
        return NewInvalidArgumentError(resp_or.status().message(),
                                       CKR_ENCRYPTED_DATA_INVALID,
                                       SOURCE_LOCATION);
      default:
        return NewError(resp_or.status().code(), resp_or.status().message(),
                        CKR_DEVICE_ERROR, SOURCE_LOCATION);
    }
  }

  kms_v1::AsymmetricDecryptResponse resp = std::move(resp_or).value();

  result_ = absl::make_unique<RsaOaepDecryptResult>(
      ciphertext,
      std::unique_ptr<std::string, ZeroDelete>(resp.release_plaintext()));
  return result_->plaintext();
}

RsaOaepDecryptResult::RsaOaepDecryptResult(
    absl::Span<const uint8_t> ciphertext,
    std::unique_ptr<std::string, ZeroDelete> plaintext)
    : plaintext_(std::move(plaintext)) {
  SHA256(ciphertext.data(), ciphertext.size(), ciphertext_hash_);
}

bool RsaOaepDecryptResult::Matches(absl::Span<const uint8_t> ciphertext) const {
  uint8_t ct_hash[32];
  SHA256(ciphertext.data(), ciphertext.size(), ct_hash);
  return std::memcmp(ct_hash, ciphertext_hash_, 32) == 0;
}

absl::Span<const uint8_t> RsaOaepDecryptResult::plaintext() const {
  return absl::MakeConstSpan(
      reinterpret_cast<const uint8_t*>(plaintext_->data()), plaintext_->size());
}

void ZeroDelete::operator()(std::string* value) const {
  if (value) {
    SafeZeroMemory(value->data(), value->size());
  }
  delete value;
}

}  // namespace kmsp11