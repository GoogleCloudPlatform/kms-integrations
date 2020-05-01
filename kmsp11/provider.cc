#include "kmsp11/provider.h"

#include "kmsp11/util/status_macros.h"
#include "kmsp11/util/string_utils.h"

namespace kmsp11 {

// TODO(bdhess): Pull this in from build configuration
const CK_VERSION kLibraryVersion = {0, 7};

StatusOr<CK_INFO> NewCkInfo() {
  CK_INFO info = {
      {CRYPTOKI_VERSION_MAJOR, CRYPTOKI_VERSION_MINOR},  // cryptokiVersion
      {0},              // manufacturerID (set with ' ' padding below)
      0,                // flags
      {0},              // libraryDescription (set with ' ' padding below)
      kLibraryVersion,  // libraryVersion
  };
  RETURN_IF_ERROR(CryptokiStrCopy("Google", info.manufacturerID));
  RETURN_IF_ERROR(CryptokiStrCopy("Cryptoki Library for Cloud KMS",
                                  info.libraryDescription));
  return info;
}

StatusOr<std::unique_ptr<Provider>> Provider::New(LibraryConfig config) {
  ASSIGN_OR_RETURN(CK_INFO info, NewCkInfo());

  std::vector<std::unique_ptr<Token>> tokens;
  tokens.reserve(config.tokens_size());
  for (const TokenConfig& tokenConfig : config.tokens()) {
    ASSIGN_OR_RETURN(std::unique_ptr<Token> token, Token::New(tokenConfig));
    tokens.emplace_back(std::move(token));
  }

  // using `new` to invoke a private constructor
  return std::unique_ptr<Provider>(new Provider(info, std::move(tokens)));
}

StatusOr<const Token*> Provider::TokenAt(CK_SLOT_ID slot_id) {
  if (slot_id >= tokens_.size()) {
    return NewError(absl::StatusCode::kNotFound,
                    absl::StrFormat("slot with ID %d does not exist", slot_id),
                    CKR_SLOT_ID_INVALID, SOURCE_LOCATION);
  }
  return tokens_[slot_id].get();
}

}  // namespace kmsp11
