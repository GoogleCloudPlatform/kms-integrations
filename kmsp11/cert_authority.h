#ifndef KMSP11_CERT_AUTHORITY_H_
#define KMSP11_CERT_AUTHORITY_H_

#include "kmsp11/util/kms_client.h"
#include "openssl/evp.h"
#include "openssl/x509v3.h"

namespace kmsp11 {

// CertAuthority implements an x.509 v3 certificate authority that generates
// certificates suitable for lookup in JCA.
class CertAuthority {
 public:
  static StatusOr<std::unique_ptr<CertAuthority>> New();

  StatusOr<bssl::UniquePtr<X509>> GenerateCert(
      absl::string_view subject_cn, EVP_PKEY* public_key,
      kms_v1::CryptoKey::CryptoKeyPurpose purpose) const;

 private:
  CertAuthority(bssl::UniquePtr<EVP_PKEY> signing_key);

  bssl::UniquePtr<EVP_PKEY> signing_key_;
  std::string issuer_cn_;
};

}  // namespace kmsp11

#endif  // KMSP11_CERT_AUTHORITY_H_
