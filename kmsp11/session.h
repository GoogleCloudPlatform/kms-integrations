#ifndef KMSP11_SESSION_H_
#define KMSP11_SESSION_H_

#include "kmsp11/token.h"

namespace kmsp11 {

// Session models a PKCS #11 Session, and in the future will contain state
// related to ongoing operations.
//
// See go/kms-pkcs11-model
class Session {
 public:
  Session(Token* token) : token_(token) {}

  Token* token() { return token_; }

 private:
  Token* token_;
};

}  // namespace kmsp11

#endif  // KMSP11_SESSION_H_
