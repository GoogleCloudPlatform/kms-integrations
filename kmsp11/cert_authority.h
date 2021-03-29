#ifndef KMSP11_CERT_AUTHORITY_H_
#define KMSP11_CERT_AUTHORITY_H_

#include "kmsp11/openssl.h"
#include "kmsp11/util/crypto_utils.h"
#include "kmsp11/util/kms_client.h"

namespace kmsp11 {

// CertAuthority implements an x.509 v3 certificate authority that generates
// certificates suitable for lookup in JCA.
class CertAuthority {
 public:
  static absl::StatusOr<std::unique_ptr<CertAuthority>> New();

  absl::StatusOr<bssl::UniquePtr<X509>> GenerateCert(
      const kms_v1::CryptoKeyVersion& ckv, EVP_PKEY* public_key) const;

 private:
  CertAuthority(bssl::UniquePtr<EVP_PKEY> signing_key);

  bssl::UniquePtr<EVP_PKEY> signing_key_;
  std::string issuer_cn_;
};

}  // namespace kmsp11

#endif  // KMSP11_CERT_AUTHORITY_H_
