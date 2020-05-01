#ifndef KMSP11_PROVIDER_H_
#define KMSP11_PROVIDER_H_

#include "kmsp11/config/config.pb.h"
#include "kmsp11/cryptoki.h"
#include "kmsp11/token.h"
#include "kmsp11/util/errors.h"
#include "kmsp11/util/status_or.h"

namespace kmsp11 {

// Provider models a "run" of a Cryptoki library, from C_Initialize to
// C_Finalize.
//
// See go/kms-pkcs11-model
class Provider {
 public:
  static StatusOr<std::unique_ptr<Provider>> New(LibraryConfig config);

  const CK_INFO& info() const { return info_; }
  const unsigned long token_count() const { return tokens_.size(); }

  StatusOr<const Token*> TokenAt(CK_SLOT_ID slot_id);

 private:
  Provider(CK_INFO info, std::vector<std::unique_ptr<Token>>&& tokens)
      : info_(info), tokens_(std::move(tokens)) {}

  const CK_INFO info_;
  const std::vector<std::unique_ptr<Token>> tokens_;
};

}  // namespace kmsp11

#endif  // KMSP11_PROVIDER_H_
