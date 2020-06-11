#ifndef KMSP11_OPERATION_RSAES_OAEP_H_
#define KMSP11_OPERATION_RSAES_OAEP_H_

#include "absl/strings/string_view.h"
#include "kmsp11/operation/crypter_interfaces.h"
#include "kmsp11/util/string_utils.h"
#include "openssl/sha.h"

namespace kmsp11 {

class RsaOaepDecryptResult;

// An implementation of DecrypterInterface that decrypts RSAES-OAEP ciphertexts
// using Cloud KMS.
class RsaOaepDecrypter : public DecrypterInterface {
 public:
  static StatusOr<std::unique_ptr<DecrypterInterface>> New(
      std::shared_ptr<Object> key, const CK_MECHANISM* mechanism);

  // Decrypt returns a span whose underlying bytes are bound to the lifetime of
  // this decrypter.
  StatusOr<absl::Span<const uint8_t>> Decrypt(
      KmsClient* client, absl::Span<const uint8_t> ciphertext) override;

  virtual ~RsaOaepDecrypter() {}

 private:
  RsaOaepDecrypter(std::shared_ptr<Object> key) : key_(key) {}

  std::shared_ptr<Object> key_;
  std::unique_ptr<RsaOaepDecryptResult> result_;
};

// A replacement for std::default_delete that zeroes before deleting.
struct ZeroDelete {
  void operator()(std::string* value) const;
};

// A datatype for storing the result of an RSAES-OAEP decryption operation.
//
// We keep the last successful decrypt result in the decrypter, whose lifecycle
// is bound to C_Decrypt*. This allows us serve multiple calls to decrypt the
// same ciphertext with a single call to KMS. Many PKCS 11 callers will call
// decrypt with the same ciphertext twice: first with a null plaintext buffer,
// in order to determine the size of the decrypted plaintext, and then again
// after they've allocated a buffer to receive the decrypted plaintext.
class RsaOaepDecryptResult {
 public:
  RsaOaepDecryptResult(absl::Span<const uint8_t> ciphertext,
                       std::unique_ptr<std::string, ZeroDelete> plaintext);

  bool Matches(absl::Span<const uint8_t> ciphertext) const;
  absl::Span<const uint8_t> plaintext() const;

 private:
  uint8_t ciphertext_hash_[32];
  std::unique_ptr<std::string, ZeroDelete> plaintext_;
};

}  // namespace kmsp11

#endif  // KMSP11_OPERATION_RSAES_OAEP_H_
