#ifndef KMSP11_SESSION_H_
#define KMSP11_SESSION_H_

#include "kmsp11/operation/operation.h"
#include "kmsp11/token.h"

namespace kmsp11 {

// Session models a PKCS #11 Session and an optional ongoing operation.
//
// See go/kms-pkcs11-model
class Session {
 public:
  Session(Token* token, KmsClient* kms_client)
      : token_(token), kms_client_(kms_client) {}

  Token* token() { return token_; }

  void ReleaseOperation();

  absl::Status FindObjectsInit(absl::Span<const CK_ATTRIBUTE> attributes);
  StatusOr<absl::Span<const CK_OBJECT_HANDLE>> FindObjects(size_t max_count);
  absl::Status FindObjectsFinal();

  absl::Status DecryptInit(std::shared_ptr<Object> key,
                           CK_MECHANISM* mechanism);
  StatusOr<absl::Span<const uint8_t>> Decrypt(
      absl::Span<const uint8_t> ciphertext);

 private:
  Token* token_;
  KmsClient* kms_client_;

  absl::Mutex op_mutex_;
  absl::optional<Operation> op_ ABSL_GUARDED_BY(op_mutex_);
};

}  // namespace kmsp11

#endif  // KMSP11_SESSION_H_
