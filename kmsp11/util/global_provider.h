#ifndef KMSP11_UTIL_GLOBAL_PROVIDER_H_
#define KMSP11_UTIL_GLOBAL_PROVIDER_H_

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "kmsp11/provider.h"

namespace kmsp11 {

// Sets the provided Provider as the global Provider for serving requests from
// this process. Returns InternalError/CKR_GENERAL_ERROR if provider is nullptr,
// or if a global provider is currently set.
absl::Status SetGlobalProvider(std::unique_ptr<Provider> provider);

// Gets a pointer to the global Provider instance, or nullptr if none is set.
Provider* GetGlobalProvider();

// Frees the global Provider instance. Returns InternalError/CKR_GENERAL_ERROR
// if no global provider instance exists.
absl::Status ReleaseGlobalProvider();

}  // namespace kmsp11

#endif  // KMSP11_UTIL_GLOBAL_PROVIDER_H_
