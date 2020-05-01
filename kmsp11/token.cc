#include "kmsp11/token.h"

#include "kmsp11/util/status_macros.h"
#include "kmsp11/util/status_or.h"
#include "kmsp11/util/string_utils.h"

namespace kmsp11 {

StatusOr<CK_SLOT_INFO> NewSlotInfo() {
  CK_SLOT_INFO info = {
      {0},                // slotDescription (set with ' ' padding below)
      {0},                // manufacturerID (set with ' ' padding below)
      CKF_TOKEN_PRESENT,  // flags
      {0, 0},             // hardwareVersion
      {0, 0},             // firmwareVersion
  };
  RETURN_IF_ERROR(
      CryptokiStrCopy("A virtual slot mapped to a key ring in Google Cloud KMS",
                      info.slotDescription));
  RETURN_IF_ERROR(CryptokiStrCopy("Google", info.manufacturerID));
  return info;
}

StatusOr<CK_TOKEN_INFO> NewTokenInfo(absl::string_view token_label) {
  CK_TOKEN_INFO info = {
      {0},  // label (set with ' ' padding below)
      {0},  // manufacturerID (set with ' ' padding below)
      {0},  // model (set with ' ' padding below)
      {0},  // serialNumber (set below)
      CKF_WRITE_PROTECTED | CKF_USER_PIN_INITIALIZED |  // flags
          CKF_TOKEN_INITIALIZED | CKF_SO_PIN_LOCKED,
      CK_EFFECTIVELY_INFINITE,     // ulMaxSessionCount
      CK_UNAVAILABLE_INFORMATION,  // ulSessionCount
      0,                           // ulMaxRwSessionCount
      CK_UNAVAILABLE_INFORMATION,  // ulRwSessionCount
      0,                           // ulMaxPinLen
      0,                           // ulMinPinLen
      CK_UNAVAILABLE_INFORMATION,  // ulTotalPublicMemory
      CK_UNAVAILABLE_INFORMATION,  // ulFreePublicMemory
      CK_UNAVAILABLE_INFORMATION,  // ulTotalPrivateMemory
      CK_UNAVAILABLE_INFORMATION,  // ulFreePrivateMemory
      {0, 0},                      // hardwareVersion
      {0, 0},                      // firmwareVersion
      {0}                          // utcTime (set below)
  };
  RETURN_IF_ERROR(CryptokiStrCopy(token_label, info.label));
  RETURN_IF_ERROR(CryptokiStrCopy("Google", info.manufacturerID));
  RETURN_IF_ERROR(CryptokiStrCopy("Cloud KMS Token", info.model));
  RETURN_IF_ERROR(CryptokiStrCopy("", info.serialNumber, '0'));
  RETURN_IF_ERROR(CryptokiStrCopy("", info.utcTime, '0'));
  return info;
}

StatusOr<std::unique_ptr<Token>> Token::New(TokenConfig tokenConfig) {
  ASSIGN_OR_RETURN(CK_SLOT_INFO slot_info, NewSlotInfo());
  ASSIGN_OR_RETURN(CK_TOKEN_INFO token_info, NewTokenInfo(tokenConfig.label()));
  return std::unique_ptr<Token>(new Token(slot_info, token_info));
}

}  // namespace kmsp11