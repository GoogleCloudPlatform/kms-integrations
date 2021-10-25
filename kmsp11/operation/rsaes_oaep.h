/*
 * Copyright 2021 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef KMSP11_OPERATION_RSAES_OAEP_H_
#define KMSP11_OPERATION_RSAES_OAEP_H_

#include <string_view>

#include "kmsp11/openssl.h"
#include "kmsp11/operation/crypter_interfaces.h"
#include "kmsp11/util/crypto_utils.h"
#include "kmsp11/util/string_utils.h"

namespace kmsp11 {

class RsaOaepDecryptResult;

// An implementation of DecrypterInterface that decrypts RSAES-OAEP ciphertexts
// using Cloud KMS.
class RsaOaepDecrypter : public DecrypterInterface {
 public:
  static absl::StatusOr<std::unique_ptr<DecrypterInterface>> New(
      std::shared_ptr<Object> key, const CK_MECHANISM* mechanism);

  // Decrypt returns a span whose underlying bytes are bound to the lifetime of
  // this decrypter.
  absl::StatusOr<absl::Span<const uint8_t>> Decrypt(
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

// An implementation of EncrypterInterface that encrypts RSAES-OAEP ciphertexts
// using BoringSSL.
class RsaOaepEncrypter : public EncrypterInterface {
 public:
  static absl::StatusOr<std::unique_ptr<EncrypterInterface>> New(
      std::shared_ptr<Object> key, const CK_MECHANISM* mechanism);

  // Encrypt returns a span whose underlying bytes are bound to the lifetime of
  // this encrypter.
  absl::StatusOr<absl::Span<const uint8_t>> Encrypt(
      KmsClient* client, absl::Span<const uint8_t> ciphertext) override;

  virtual ~RsaOaepEncrypter() {}

 private:
  RsaOaepEncrypter(std::shared_ptr<Object> object,
                   bssl::UniquePtr<EVP_PKEY> key)
      : object_(object),
        key_(std::move(key)),
        ciphertext_(object->algorithm().key_bit_length / 8) {}

  std::shared_ptr<Object> object_;
  bssl::UniquePtr<EVP_PKEY> key_;
  std::vector<uint8_t> ciphertext_;
};

}  // namespace kmsp11

#endif  // KMSP11_OPERATION_RSAES_OAEP_H_
