#include "kmsp11/token.h"

#include "kmsp11/util/errors.h"
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

StatusOr<std::unique_ptr<Token>> Token::New(CK_SLOT_ID slot_id,
                                            TokenConfig token_config) {
  ASSIGN_OR_RETURN(CK_SLOT_INFO slot_info, NewSlotInfo());
  ASSIGN_OR_RETURN(CK_TOKEN_INFO token_info,
                   NewTokenInfo(token_config.label()));

  // using `new` to invoke a private constructor
  return std::unique_ptr<Token>(new Token(slot_id, slot_info, token_info));
}

CK_SESSION_INFO Token::session_info() const {
  absl::ReaderMutexLock l(&session_mutex_);

  return CK_SESSION_INFO{
      slot_id_,            // slotID
      session_state_,      // state
      CKF_SERIAL_SESSION,  // flags
      0,                   // ulDeviceError
  };
}

absl::Status Token::Login(CK_USER_TYPE user) {
  absl::WriterMutexLock l(&session_mutex_);

  switch (user) {
    case CKU_USER:
      break;
    case CKU_SO:
      return NewError(absl::StatusCode::kPermissionDenied,
                      "login as CKU_SO is not permitted", CKR_PIN_LOCKED,
                      SOURCE_LOCATION);
    case CKU_CONTEXT_SPECIFIC:
      // See description of CKA_ALWAYS_AUTHENTICATE at
      // http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/pkcs11-base-v2.40.html#_Toc322855286
      return NewError(absl::StatusCode::kPermissionDenied,
                      "CKA_ALWAYS_AUTHENTICATE is not true on this token",
                      CKR_OPERATION_NOT_INITIALIZED, SOURCE_LOCATION);
    default:
      return NewInvalidArgumentError(
          absl::StrFormat("unknown user type: %#x", user),
          CKR_USER_TYPE_INVALID, SOURCE_LOCATION);
  }

  if (session_state_ == CKS_RO_USER_FUNCTIONS) {
    return FailedPreconditionError("user is already logged in",
                                   CKR_USER_ALREADY_LOGGED_IN, SOURCE_LOCATION);
  }
  if (session_state_ != CKS_RO_PUBLIC_SESSION) {
    return NewInternalError(
        absl::StrFormat("unexpected state %#x", session_state_),
        SOURCE_LOCATION);
  }

  session_state_ = CKS_RO_USER_FUNCTIONS;
  return absl::OkStatus();
}

absl::Status Token::Logout() {
  absl::WriterMutexLock l(&session_mutex_);

  if (session_state_ == CKS_RO_PUBLIC_SESSION) {
    return FailedPreconditionError("user is not logged in",
                                   CKR_USER_NOT_LOGGED_IN, SOURCE_LOCATION);
  }
  if (session_state_ != CKS_RO_USER_FUNCTIONS) {
    return NewInternalError(
        absl::StrFormat("unexpected state %#x", session_state_),
        SOURCE_LOCATION);
  }

  session_state_ = CKS_RO_PUBLIC_SESSION;
  return absl::OkStatus();
}

}  // namespace kmsp11