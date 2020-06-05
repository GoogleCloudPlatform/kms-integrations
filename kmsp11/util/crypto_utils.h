#ifndef KMSP11_UTIL_CRYPTO_UTILS_H_
#define KMSP11_UTIL_CRYPTO_UTILS_H_

#include "kmsp11/util/status_or.h"
#include "openssl/evp.h"

namespace kmsp11 {

// Marshals EC Parameters (always of choice NamedCurve) in DER format for the
// provided key.
//
// Required to populate the attribute CKA_EC_PARAMS:
// http://docs.oasis-open.org/pkcs11/pkcs11-curr/v2.40/errata01/os/pkcs11-curr-v2.40-errata01-os-complete.html#_Toc468937842
StatusOr<std::string> MarshalEcParametersDer(const EC_KEY* key);

// Marshals the provided EC public key in DER format.
//
// Required to populate the attribute CKA_EC_POINT:
// http://docs.oasis-open.org/pkcs11/pkcs11-curr/v2.40/errata01/os/pkcs11-curr-v2.40-errata01-os-complete.html#_Toc416960012
StatusOr<std::string> MarshalEcPointDer(const EC_KEY* key);

// Marshals a public key to X.509 SubjectPublicKeyInfo DER format.
//
// Required to populate the attribute CKA_PUBLIC_KEY_INFO:
// http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/errata01/os/pkcs11-base-v2.40-errata01-os-complete.html#_Toc441755781
StatusOr<std::string> MarshalX509PublicKeyDer(const EVP_PKEY* key);

// Parses a public key in X.509 SubjectPublicKeyInfo PEM format. Returns
// InvalidArgument if the provided key is malformed.
// Required to parse PEM public keys retrieved from Cloud KMS.
StatusOr<bssl::UniquePtr<EVP_PKEY>> ParseX509PublicKeyPem(
    absl::string_view public_key_pem);

// Retrieves len bytes of randomness from Boring's CSPRNG.
std::string RandBytes(size_t len);

// Retrieves the contents of BoringSSL's error stack, and dumps it to a string.
std::string SslErrorToString();

// A UniformRandomBitGenerator backed by Boring's CSPRNG.
// https://en.cppreference.com/w/cpp/named_req/UniformRandomBitGenerator
class BoringBitGenerator {
 public:
  using result_type = uint64_t;

  inline static constexpr uint64_t min() {
    return std::numeric_limits<uint64_t>::min();
  }

  inline static constexpr uint64_t max() {
    return std::numeric_limits<uint64_t>::max();
  }

  uint64_t operator()();
};

}  // namespace kmsp11

#endif  // KMSP11_UTIL_CRYPTO_UTILS_H_
