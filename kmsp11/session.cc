#include "kmsp11/session.h"

#include "kmsp11/util/errors.h"
#include "kmsp11/util/status_macros.h"

namespace kmsp11 {

void Session::ReleaseOperation() {
  absl::MutexLock l(&op_mutex_);
  op_ = absl::nullopt;
}

absl::Status Session::FindObjectsInit(
    absl::Span<const CK_ATTRIBUTE> attributes) {
  absl::MutexLock l(&op_mutex_);

  if (op_.has_value()) {
    return OperationActiveError(SOURCE_LOCATION);
  }

  std::vector<CK_OBJECT_HANDLE> results =
      token_->FindObjects([&attributes](const Object& o) -> bool {
        for (const CK_ATTRIBUTE& attr : attributes) {
          if (!o.attributes().Contains(attr)) {
            return false;
          }
        }
        return true;
      });

  op_ = FindOp(results);
  return absl::OkStatus();
}

StatusOr<absl::Span<const CK_OBJECT_HANDLE>> Session::FindObjects(
    size_t max_count) {
  absl::MutexLock l(&op_mutex_);

  if (!op_.has_value() || !absl::holds_alternative<FindOp>(op_.value())) {
    return OperationNotInitializedError("find", SOURCE_LOCATION);
  }

  FindOp& op = absl::get<FindOp>(op_.value());
  return op.Next(max_count);
}

absl::Status Session::FindObjectsFinal() {
  absl::MutexLock l(&op_mutex_);

  if (!op_.has_value() || !absl::holds_alternative<FindOp>(op_.value())) {
    return OperationNotInitializedError("find", SOURCE_LOCATION);
  }

  op_ = absl::nullopt;
  return absl::OkStatus();
}

absl::Status Session::DecryptInit(std::shared_ptr<Object> key,
                                  CK_MECHANISM* mechanism) {
  absl::MutexLock l(&op_mutex_);

  if (op_.has_value()) {
    return OperationActiveError(SOURCE_LOCATION);
  }

  ASSIGN_OR_RETURN(op_, NewDecryptOp(key, mechanism));
  return absl::OkStatus();
}

StatusOr<absl::Span<const uint8_t>> Session::Decrypt(
    absl::Span<const uint8_t> ciphertext) {
  absl::MutexLock l(&op_mutex_);

  if (!op_.has_value() || !absl::holds_alternative<DecryptOp>(op_.value())) {
    return OperationNotInitializedError("decrypt", SOURCE_LOCATION);
  }

  return absl::get<DecryptOp>(op_.value())->Decrypt(kms_client_, ciphertext);
}

absl::Status Session::EncryptInit(std::shared_ptr<Object> key,
                                  CK_MECHANISM* mechanism) {
  absl::MutexLock l(&op_mutex_);

  if (op_.has_value()) {
    return OperationActiveError(SOURCE_LOCATION);
  }

  ASSIGN_OR_RETURN(op_, NewEncryptOp(key, mechanism));
  return absl::OkStatus();
}

StatusOr<absl::Span<const uint8_t>> Session::Encrypt(
    absl::Span<const uint8_t> plaintext) {
  absl::MutexLock l(&op_mutex_);

  if (!op_.has_value() || !absl::holds_alternative<EncryptOp>(op_.value())) {
    return OperationNotInitializedError("encrypt", SOURCE_LOCATION);
  }

  return absl::get<EncryptOp>(op_.value())->Encrypt(kms_client_, plaintext);
}

absl::Status Session::SignInit(std::shared_ptr<Object> key,
                               CK_MECHANISM* mechanism) {
  absl::MutexLock l(&op_mutex_);

  if (op_.has_value()) {
    return OperationActiveError(SOURCE_LOCATION);
  }

  ASSIGN_OR_RETURN(op_, NewSignOp(key, mechanism));
  return absl::OkStatus();
}

absl::Status Session::Sign(absl::Span<const uint8_t> digest,
                           absl::Span<uint8_t> signature) {
  absl::MutexLock l(&op_mutex_);

  if (!op_.has_value() || !absl::holds_alternative<SignOp>(op_.value())) {
    return OperationNotInitializedError("sign", SOURCE_LOCATION);
  }

  return absl::get<SignOp>(op_.value())->Sign(kms_client_, digest, signature);
}

StatusOr<size_t> Session::SignatureLength() {
  absl::MutexLock l(&op_mutex_);

  if (!op_.has_value() || !absl::holds_alternative<SignOp>(op_.value())) {
    return OperationNotInitializedError("sign", SOURCE_LOCATION);
  }

  return absl::get<SignOp>(op_.value())->signature_length();
}

absl::Status Session::VerifyInit(std::shared_ptr<Object> key,
                                 CK_MECHANISM* mechanism) {
  absl::MutexLock l(&op_mutex_);

  if (op_.has_value()) {
    return OperationActiveError(SOURCE_LOCATION);
  }

  ASSIGN_OR_RETURN(op_, NewVerifyOp(key, mechanism));
  return absl::OkStatus();
}

absl::Status Session::Verify(absl::Span<const uint8_t> digest,
                             absl::Span<const uint8_t> signature) {
  absl::MutexLock l(&op_mutex_);

  if (!op_.has_value() || !absl::holds_alternative<VerifyOp>(op_.value())) {
    return OperationNotInitializedError("verify", SOURCE_LOCATION);
  }

  return absl::get<VerifyOp>(op_.value())
      ->Verify(kms_client_, digest, signature);
}

}  // namespace kmsp11