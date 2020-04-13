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

StatusOr<Provider> Provider::New() {
  ASSIGN_OR_RETURN(CK_INFO info, NewCkInfo());
  return Provider(info);
}

}  // namespace kmsp11
