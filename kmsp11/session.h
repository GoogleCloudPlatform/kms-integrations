#ifndef KMSP11_SESSION_H_
#define KMSP11_SESSION_H_

#include "kmsp11/operation/operation.h"
#include "kmsp11/token.h"

namespace kmsp11 {

enum class SessionType { kReadOnly, kReadWrite };

struct AsymmetricHandleSet {
  CK_OBJECT_HANDLE private_key_handle;
  CK_OBJECT_HANDLE public_key_handle;
};

// Session models a PKCS #11 Session and an optional ongoing operation.
//
// See go/kms-pkcs11-model
class Session {
 public:
  Session(Token* token, SessionType session_type, KmsClient* kms_client)
      : token_(token), session_type_(session_type), kms_client_(kms_client) {}

  Token* token() const { return token_; }
  CK_SESSION_INFO info() const;

  void ReleaseOperation();

  absl::Status FindObjectsInit(absl::Span<const CK_ATTRIBUTE> attributes);
  absl::StatusOr<absl::Span<const CK_OBJECT_HANDLE>> FindObjects(
      size_t max_count);
  absl::Status FindObjectsFinal();

  absl::Status DecryptInit(std::shared_ptr<Object> key,
                           CK_MECHANISM* mechanism);
  absl::StatusOr<absl::Span<const uint8_t>> Decrypt(
      absl::Span<const uint8_t> ciphertext);

  absl::Status EncryptInit(std::shared_ptr<Object> key,
                           CK_MECHANISM* mechanism);
  absl::StatusOr<absl::Span<const uint8_t>> Encrypt(
      absl::Span<const uint8_t> plaintext);

  absl::Status SignInit(std::shared_ptr<Object> key, CK_MECHANISM* mechanism);
  absl::Status Sign(absl::Span<const uint8_t> digest,
                    absl::Span<uint8_t> signature);
  absl::StatusOr<size_t> SignatureLength();

  absl::Status VerifyInit(std::shared_ptr<Object> key, CK_MECHANISM* mechanism);
  absl::Status Verify(absl::Span<const uint8_t> digest,
                      absl::Span<const uint8_t> signature);

  absl::StatusOr<AsymmetricHandleSet> GenerateKeyPair(
      const CK_MECHANISM& mechanism,
      absl::Span<const CK_ATTRIBUTE> public_key_attrs,
      absl::Span<const CK_ATTRIBUTE> private_key_attrs);

  absl::Status DestroyObject(std::shared_ptr<Object> object);

 private:
  Token* token_;
  const SessionType session_type_;
  KmsClient* kms_client_;

  absl::Mutex op_mutex_;
  absl::optional<Operation> op_ ABSL_GUARDED_BY(op_mutex_);
};

}  // namespace kmsp11

#endif  // KMSP11_SESSION_H_
