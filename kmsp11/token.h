#ifndef KMSP11_TOKEN_H_
#define KMSP11_TOKEN_H_

#include "absl/status/status.h"
#include "absl/synchronization/mutex.h"
#include "kmsp11/config/config.pb.h"
#include "kmsp11/cryptoki.h"
#include "kmsp11/object.h"
#include "kmsp11/util/handle_map.h"
#include "kmsp11/util/kms_client.h"
#include "kmsp11/util/status_or.h"

namespace kmsp11 {

// Token models a PKCS #11 Token, and logically maps to a key ring in
// Cloud KMS.
//
// See go/kms-pkcs11-model
class Token {
 public:
  static StatusOr<std::unique_ptr<Token>> New(CK_SLOT_ID slot_id,
                                              TokenConfig token_config,
                                              KmsClient* kms_client,
                                              bool generate_certs = false);

  CK_SLOT_ID slot_id() const { return slot_id_; }
  const CK_SLOT_INFO& slot_info() const { return slot_info_; }
  const CK_TOKEN_INFO& token_info() const { return token_info_; }
  CK_SESSION_INFO session_info() const;

  absl::Status Login(CK_USER_TYPE user_type);
  absl::Status Logout();

  inline StatusOr<std::shared_ptr<Object>> GetObject(
      CK_OBJECT_HANDLE object_handle) const {
    return objects_->Get(object_handle);
  }
  std::vector<CK_OBJECT_HANDLE> FindObjects(
      std::function<bool(const Object&)> predicate) const;

 private:
  Token(CK_SLOT_ID slot_id, CK_SLOT_INFO slot_info, CK_TOKEN_INFO token_info,
        std::unique_ptr<HandleMap<Object>> objects)
      : slot_id_(slot_id),
        slot_info_(slot_info),
        token_info_(token_info),
        objects_(std::move(objects)),
        session_state_(CKS_RO_PUBLIC_SESSION) {}

  const CK_SLOT_ID slot_id_;
  const CK_SLOT_INFO slot_info_;
  const CK_TOKEN_INFO token_info_;
  std::unique_ptr<HandleMap<Object>> objects_;

  // All sessions with the same token have the same state (rather than session
  // state being per-session, which seems like the more obvious choice.)
  // http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/pkcs11-base-v2.40.html#_Toc235002343
  mutable absl::Mutex session_mutex_;
  CK_STATE session_state_ ABSL_GUARDED_BY(session_mutex_);
};

}  // namespace kmsp11

#endif  // KMSP11_TOKEN_H_
