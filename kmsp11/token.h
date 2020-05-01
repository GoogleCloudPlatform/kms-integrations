#ifndef KMSP11_TOKEN_H_
#define KMSP11_TOKEN_H_

#include "kmsp11/config/config.pb.h"
#include "kmsp11/cryptoki.h"
#include "kmsp11/util/status_or.h"

namespace kmsp11 {

// Tokens models a PKCS #11 Token, and logically maps to a key ring in
// Cloud KMS.
//
// See go/kms-pkcs11-model
class Token {
 public:
  static StatusOr<std::unique_ptr<Token>> New(TokenConfig tokenConfig);

  const CK_SLOT_INFO& slot_info() const { return slot_info_; }
  const CK_TOKEN_INFO& token_info() const { return token_info_; }

 private:
  Token(CK_SLOT_INFO slot_info, CK_TOKEN_INFO token_info)
      : slot_info_(slot_info), token_info_(token_info) {}
  const CK_SLOT_INFO slot_info_;
  const CK_TOKEN_INFO token_info_;
};

}  // namespace kmsp11

#endif  // KMSP11_TOKEN_H_
