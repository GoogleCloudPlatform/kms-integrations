#ifndef KMSP11_UTIL_CRYPTO_UTILS_H_
#define KMSP11_UTIL_CRYPTO_UTILS_H_

#include "absl/time/time.h"
#include "kmsp11/util/status_or.h"
#include "openssl/evp.h"

namespace kmsp11 {

// Convert an ASN1_TIME structure to an absl::Time.
StatusOr<absl::Time> Asn1TimeToAbsl(const ASN1_TIME* time);

// Converts a signature in ASN.1 format (as returned by OpenSSL and Cloud KMS)
// into IEEE P-1363 format (as required by PKCS #11).
StatusOr<std::vector<uint8_t>> EcdsaSigAsn1ToP1363(absl::string_view asn1_sig,
                                                   const EC_GROUP* group);

// Returns the length of a signature in IEEE P-1363 format (with leading zeroes)
// for the provided group.
int EcdsaSigLengthP1363(const EC_GROUP* group);

// Verifies that the provided signature in IEEE P-1363 format is a valid
// signature over digest.
absl::Status EcdsaVerifyP1363(EC_KEY* public_key, const EVP_MD* hash,
                              absl::Span<const uint8_t> digest,
                              absl::Span<const uint8_t> signature);

// Encrypts plaintext using RSAES-OAEP with MGF-1, and writes it to ciphertext.
// Ciphertext size must be exactly equal to the RSA modulus size. Hash is used
// in both OAEP and MGF-1; OAEP labels are not supported.
absl::Status EncryptRsaOaep(EVP_PKEY* key, const EVP_MD* hash,
                            absl::Span<const uint8_t> plaintext,
                            absl::Span<uint8_t> ciphertext);

// Marshals an ASN.1 integer in DER format.
StatusOr<std::string> MarshalAsn1Integer(ASN1_INTEGER* value);

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

// Marshals an X.509 certificate in DER format.
StatusOr<std::string> MarshalX509CertificateDer(X509* cert);

// Marshals an X.509 name (subject or issuer) in DER format.
StatusOr<std::string> MarshalX509Name(X509_NAME* value);

// Marshals a public key to X.509 SubjectPublicKeyInfo DER format.
//
// Required to populate the attribute CKA_PUBLIC_KEY_INFO:
// http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/errata01/os/pkcs11-base-v2.40-errata01-os-complete.html#_Toc441755781
StatusOr<std::string> MarshalX509PublicKeyDer(const EVP_PKEY* key);

// Parses a private key in PKCS #8 PrivateKey PEM format. Returns
// InvalidArgument if the provided key is malformed.
StatusOr<bssl::UniquePtr<EVP_PKEY>> ParsePkcs8PrivateKeyPem(
    absl::string_view private_key_pem);

// Marshals an ASN.1 DigestInfo in DER format.
StatusOr<std::string> MarshalX509Sig(X509_SIG* value);

// Parses a public key in X.509 SubjectPublicKeyInfo DER format. Returns
// InvalidArgument if the provided key is malformed.
StatusOr<bssl::UniquePtr<EVP_PKEY>> ParseX509PublicKeyDer(
    absl::string_view public_key_der);

// Parses a public key in X.509 SubjectPublicKeyInfo PEM format. Returns
// InvalidArgument if the provided key is malformed.
// Required to parse PEM public keys retrieved from Cloud KMS.
StatusOr<bssl::UniquePtr<EVP_PKEY>> ParseX509PublicKeyPem(
    absl::string_view public_key_pem);

// Retrieves len bytes of randomness from Boring's CSPRNG.
std::string RandBytes(size_t len);

// Verifies that the provided RSA PKCS1 signature is valid over digest.
absl::Status RsaVerifyPkcs1(RSA* public_key, const EVP_MD* hash,
                            absl::Span<const uint8_t> digest,
                            absl::Span<const uint8_t> signature);

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
