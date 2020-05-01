#include "absl/status/status.h"
#include "absl/types/optional.h"
#include "kmsp11/config/config.h"
#include "kmsp11/cryptoki.h"
#include "kmsp11/main/function_list.h"
#include "kmsp11/provider.h"
#include "kmsp11/util/errors.h"
#include "kmsp11/util/status_macros.h"

namespace kmsp11 {

static CK_FUNCTION_LIST function_list = NewFunctionList();
static std::unique_ptr<Provider> provider;

StatusOr<Provider*> GetProvider() {
  if (!provider) {
    return NotInitializedError(SOURCE_LOCATION);
  }
  return provider.get();
}

StatusOr<const Token*> GetToken(CK_SLOT_ID slot_id) {
  ASSIGN_OR_RETURN(Provider * provider, GetProvider());
  return provider->TokenAt(slot_id);
}

// Initialize the library.
// http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/pkcs11-base-v2.40.html#_Toc235002322
absl::Status Initialize(CK_VOID_PTR pInitArgs) {
  if (provider) {
    return NewError(absl::StatusCode::kFailedPrecondition,
                    "the library is already initialized",
                    CKR_CRYPTOKI_ALREADY_INITIALIZED, SOURCE_LOCATION);
  }

  auto* init_args = static_cast<CK_C_INITIALIZE_ARGS*>(pInitArgs);

  LibraryConfig config;
  if (init_args && init_args->pReserved) {
    // This behavior isn't part of the spec, but there are numerous libraries
    // in the wild that allow specifying a config file in pInitArgs->pReserved.
    // There's also support for providing config this way in the OpenSSL engine:
    // https://github.com/OpenSC/libp11/blob/4084f83ee5ea51353facf151126b7d6d739d0784/src/eng_front.c#L62
    ASSIGN_OR_RETURN(
        config, LoadConfigFromFile(static_cast<char*>(init_args->pReserved)));
  } else {
    ASSIGN_OR_RETURN(config, LoadConfigFromEnvironment());
  }

  ASSIGN_OR_RETURN(provider, Provider::New(config));
  return absl::OkStatus();
}

// Shut down the library.
// http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/pkcs11-base-v2.40.html#_Toc383864872
absl::Status Finalize(CK_VOID_PTR pReserved) {
  if (!provider) {
    return NotInitializedError(SOURCE_LOCATION);
  }
  provider = nullptr;
  return absl::OkStatus();
}

// Get basic information about the library.
// http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/pkcs11-base-v2.40.html#_Toc235002324
absl::Status GetInfo(CK_INFO_PTR pInfo) {
  ASSIGN_OR_RETURN(const Provider* provider, GetProvider());
  if (!pInfo) {
    return NullArgumentError("pInfo", SOURCE_LOCATION);
  }

  *pInfo = provider->info();
  return absl::OkStatus();
}

// Get pointers to the functions exposed in this library.
// http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/pkcs11-base-v2.40.html#_Toc319313512
absl::Status GetFunctionList(CK_FUNCTION_LIST_PTR_PTR ppFunctionList) {
  // Note that GetFunctionList is the only Cryptoki function that may be called
  // before the library is initialized.
  if (!ppFunctionList) {
    return NullArgumentError("ppFunctionList", SOURCE_LOCATION);
  }
  *ppFunctionList = &function_list;
  return absl::OkStatus();
}

// Get the list of slots in this library.
// http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/pkcs11-base-v2.40.html#_Toc235002327
// Note that tokenPresent is always ignored in our library, since we do not have
// removable tokens.
absl::Status GetSlotList(CK_BBOOL tokenPresent, CK_SLOT_ID_PTR pSlotList,
                         CK_ULONG_PTR pulCount) {
  ASSIGN_OR_RETURN(const Provider* provider, GetProvider());
  if (!pulCount) {
    return NullArgumentError("pulCount", SOURCE_LOCATION);
  }

  if (!pSlotList) {
    *pulCount = provider->token_count();
    return absl::OkStatus();
  }

  if (*pulCount < provider->token_count()) {
    absl::Status result =
        OutOfRangeError(absl::StrFormat("*pulCount=%d but there are %d tokens",
                                        *pulCount, provider->token_count()),
                        SOURCE_LOCATION);
    *pulCount = provider->token_count();
    return result;
  }

  for (int i = 0; i < provider->token_count(); i++) {
    pSlotList[i] = i;
  }
  *pulCount = provider->token_count();
  return absl::OkStatus();
}

// Get information about a slot in the system.
// http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/pkcs11-base-v2.40.html#_Toc235002328
absl::Status GetSlotInfo(CK_SLOT_ID slotID, CK_SLOT_INFO_PTR pInfo) {
  ASSIGN_OR_RETURN(const Token* token, GetToken(slotID));
  if (!pInfo) {
    return NullArgumentError("pInfo", SOURCE_LOCATION);
  }

  *pInfo = token->slot_info();
  return absl::OkStatus();
}

// Get information about a token in the system.
// http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/pkcs11-base-v2.40.html#_Toc235002329
absl::Status GetTokenInfo(CK_SLOT_ID slotID, CK_TOKEN_INFO_PTR pInfo) {
  ASSIGN_OR_RETURN(const Token* token, GetToken(slotID));
  if (!pInfo) {
    return NullArgumentError("pInfo", SOURCE_LOCATION);
  }

  *pInfo = token->token_info();
  return absl::OkStatus();
}

}  // namespace kmsp11
