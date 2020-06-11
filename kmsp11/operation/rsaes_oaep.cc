#include "kmsp11/operation/rsaes_oaep.h"

#include "kmsp11/object.h"
#include "kmsp11/operation/preconditions.h"
#include "kmsp11/util/cleanup.h"
#include "kmsp11/util/errors.h"
#include "kmsp11/util/status_macros.h"
#include "kmsp11/util/string_utils.h"
#include "openssl/sha.h"

namespace kmsp11 {

StatusOr<std::unique_ptr<DecrypterInterface>> RsaOaepDecrypter::New(
    std::shared_ptr<Object> key, const CK_MECHANISM* mechanism) {
  RETURN_IF_ERROR(CheckKeyPreconditions(CKK_RSA, CKO_PRIVATE_KEY,
                                        CKM_RSA_PKCS_OAEP, key.get()));
  return std::unique_ptr<DecrypterInterface>(new RsaOaepDecrypter(key));
}

StatusOr<absl::Span<const uint8_t>> RsaOaepDecrypter::Decrypt(
    KmsClient* client, absl::Span<const uint8_t> ciphertext) {
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
  Cleanup c([&req]() -> void { ZeroDelete()(req.release_ciphertext()); });

  StatusOr<kms_v1::AsymmetricDecryptResponse> resp_or =
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
  decrypted_plaintext_ =
      std::unique_ptr<std::string, ZeroDelete>(resp.release_plaintext());
  return absl::MakeConstSpan(
      reinterpret_cast<const uint8_t*>(decrypted_plaintext_->data()),
      decrypted_plaintext_->size());
}

void ZeroDelete::operator()(std::string* value) const {
  if (value) {
    // TODO(b/156502733): discussion options with ISE
    // See http://b/156502733#comment23
    // https://wiki.sei.cmu.edu/confluence/display/c/MSC06-C.+Beware+of+compiler+optimizations
    volatile char* p = &*value->begin();
    size_t s = value->size();
    while (s--) {
      *p++ = 0;
    }
  }
  delete value;
}

}  // namespace kmsp11