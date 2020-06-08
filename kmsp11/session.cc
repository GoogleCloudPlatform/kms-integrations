#include "kmsp11/session.h"

#include "kmsp11/util/errors.h"

namespace kmsp11 {

namespace {
static const char* kOperationName = "find";
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

  op_.emplace(FindOp(results));
  return absl::OkStatus();
}

StatusOr<absl::Span<const CK_OBJECT_HANDLE>> Session::FindObjects(
    size_t max_count) {
  absl::MutexLock l(&op_mutex_);

  if (!op_.has_value() || !absl::holds_alternative<FindOp>(op_.value())) {
    return OperationNotInitializedError(kOperationName, SOURCE_LOCATION);
  }

  FindOp& op = absl::get<FindOp>(op_.value());
  return op.Next(max_count);
}

absl::Status Session::FindObjectsFinal() {
  absl::MutexLock l(&op_mutex_);

  if (!op_.has_value() || !absl::holds_alternative<FindOp>(op_.value())) {
    return OperationNotInitializedError(kOperationName, SOURCE_LOCATION);
  }

  op_.reset();
  return absl::OkStatus();
}

}  // namespace kmsp11