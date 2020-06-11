#ifndef KMSP11_OPERATION_RSAES_OAEP_H_
#define KMSP11_OPERATION_RSAES_OAEP_H_

#include "absl/strings/string_view.h"
#include "kmsp11/operation/crypter_interfaces.h"
#include "kmsp11/util/string_utils.h"

namespace kmsp11 {

// A replacement for std::default_delete that zeroes before deleting.
struct ZeroDelete {
  void operator()(std::string* value) const;
};

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
  std::unique_ptr<std::string, ZeroDelete> decrypted_plaintext_;
};

}  // namespace kmsp11

#endif  // KMSP11_OPERATION_RSAES_OAEP_H_
