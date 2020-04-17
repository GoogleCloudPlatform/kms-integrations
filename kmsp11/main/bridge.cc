#include "absl/status/status.h"
#include "absl/types/optional.h"
#include "kmsp11/cryptoki.h"
#include "kmsp11/main/function_list.h"
#include "kmsp11/provider.h"
#include "kmsp11/util/errors.h"
#include "kmsp11/util/status_macros.h"

namespace kmsp11 {

static CK_FUNCTION_LIST function_list = NewFunctionList();
static absl::optional<Provider> provider;

StatusOr<Provider*> GetProvider() {
  if (!provider.has_value()) {
    return NotInitializedError(SOURCE_LOCATION);
  }
  return &provider.value();
}

// Initialize the library.
// http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/pkcs11-base-v2.40.html#_Toc235002322
absl::Status Initialize(CK_VOID_PTR initArgs) {
  if (provider.has_value()) {
    return NewError(absl::StatusCode::kFailedPrecondition,
                    "the library is already initialized",
                    CKR_CRYPTOKI_ALREADY_INITIALIZED, SOURCE_LOCATION);
  }
  ASSIGN_OR_RETURN(provider, Provider::New());
  return absl::OkStatus();
}

// Shut down the library.
// http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/pkcs11-base-v2.40.html#_Toc383864872
absl::Status Finalize(CK_VOID_PTR reserved) {
  if (!provider.has_value()) {
    return NotInitializedError(SOURCE_LOCATION);
  }
  provider = absl::nullopt;
  return absl::OkStatus();
}

// Get basic information about the library.
// http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/pkcs11-base-v2.40.html#_Toc235002324
absl::Status GetInfo(CK_INFO_PTR info) {
  ASSIGN_OR_RETURN(Provider * provider, GetProvider());
  *info = provider->info();
  return absl::OkStatus();
}

// Get pointers to the functions exposed in this library.
// http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/pkcs11-base-v2.40.html#_Toc319313512
absl::Status GetFunctionList(CK_FUNCTION_LIST_PTR_PTR ppFunctionList) {
  // Note that GetFunctionList is the only Cryptoki function that may be called
  // before the library is initialized.
  *ppFunctionList = &function_list;
  return absl::OkStatus();
}

}  // namespace kmsp11
