#include "kmsp11/util/global_provider.h"

#include "kmsp11/util/errors.h"

namespace kmsp11 {
namespace {
// The singleton provider instance associated with the running process. The
// value is nullptr if the provider is not currently initialized.
//
// This is a bare pointer to comply with the style guide rules around variables
// with static storage duration. Specifically, use of a unique_ptr here could
// lead to difficult-to-debug undefined behavior at process shutdown.
// See go/ub-examples#non-trivially-destructible-staticglobal-variables;
Provider* static_provider = nullptr;

}  // namespace

Provider* GetGlobalProvider() { return static_provider; }

absl::Status SetGlobalProvider(std::unique_ptr<Provider> provider) {
  if (!provider) {
    return NewInternalError("nullptr passed to SetGlobalProvider",
                            SOURCE_LOCATION);
  }
  if (static_provider) {
    return NewInternalError(
        "SetGlobalProvider was invoked, but a global provider has "
        "already been set.",
        SOURCE_LOCATION);
  }
  static_provider = provider.release();
  return absl::OkStatus();
}

absl::Status ReleaseGlobalProvider() {
  if (!static_provider) {
    return NewInternalError(
        "ReleaseGlobalProvider was invoked, but a global provider has not been "
        "set.",
        SOURCE_LOCATION);
  }
  delete static_provider;
  static_provider = nullptr;
  return absl::OkStatus();
}

}  // namespace kmsp11
