#ifndef KMSP11_UTIL_STATUS_OR_H_
#define KMSP11_UTIL_STATUS_OR_H_

#include "absl/status/status.h"
#include "absl/types/variant.h"
#include "glog/logging.h"

namespace kmsp11 {

// StatusOr<T> is the type safe union of an absl::Status object and a T
// object.
//
// The primary use-case for StatusOr<T> is as the return value of a
// function which may fail.
//
// Example usage of a StatusOr<T>:
//
//  StatusOr<Foo> result = DoBigCalculationThatCouldFail();
//  if (result.ok()) {
//    result.value().DoSomethingCool();
//  } else {
//    LOG(ERROR) << result.status();
//  }
//
// Note to maintainers: this class will become obsolete when Abseil releases
// absl::StatusOr. In the interim, care should be taken to ensure that the
// interface remains compatible with the proposal at go/absl-statusor, to ease
// the eventual migration.
template <typename T>
class ABSL_MUST_USE_RESULT StatusOr {
 public:
  using element_type = T;

  // Constructs a new StatusOr by copying t.
  inline StatusOr(const T& t) : value_(t) {}

  // Constructs a new StatusOr by forwarding t.
  inline StatusOr(T&& t) : value_(std::forward<T>(t)) {}

  // Constructs a new StatusOr with the provided status. It is an error to
  // specify an OK status (this requirement is CHECKed).
  StatusOr(const absl::Status& status);

  // Returns true if this StatusOr holds a T object.
  inline bool ok() const { return absl::holds_alternative<T>(value_); }

  // Return the absl::Status held by this StatusOr, or absl::OkStatus if this
  // StatusOr holds a T.
  const absl::Status& status() const&;

  // Returns a const reference to the T held by this StatusOr, or CHECK-fails if
  // `!this->ok()`.
  const T& value() const&;

  // Returns a const rvalue reference to the T held by this StatusOr, or
  // CHECK-fails if `!this->ok()`.
  T&& value() &&;

  // Ignores any errors. This method does nothing except potentially suppress
  // complaints from any tools that are checking that errors are not dropped on
  // the floor.
  inline void IgnoreError() const {}

 private:
  absl::variant<absl::Status, T> value_;
  void CheckOk() const;
};

template <typename T>
inline StatusOr<T>::StatusOr(const absl::Status& status) : value_(status) {
  CHECK(!status.ok()) << "attempted to create StatusOr from OK status: "
                      << status.ToString();
}

template <typename T>
inline void StatusOr<T>::CheckOk() const {
  CHECK(ok()) << "attempted to retrieve value from non-OK StatusOr: "
              << absl::get<absl::Status>(value_);
}

template <typename T>
inline const absl::Status& StatusOr<T>::status() const& {
  if (ok()) {
    static const absl::Status kOkStatus = absl::OkStatus();
    return kOkStatus;
  }
  return absl::get<absl::Status>(value_);
}

template <typename T>
inline const T& StatusOr<T>::value() const& {
  CheckOk();
  return absl::get<T>(value_);
}

template <typename T>
inline T&& StatusOr<T>::value() && {
  CheckOk();
  return std::move(absl::get<T>(value_));
}

}  // namespace kmsp11

#endif  // KMSP11_UTIL_STATUS_OR_H_
