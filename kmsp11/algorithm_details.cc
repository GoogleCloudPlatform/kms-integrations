#include "kmsp11/algorithm_details.h"

#include "absl/container/flat_hash_map.h"
#include "kmsp11/util/errors.h"

namespace kmsp11 {

static const auto* const kAlgorithmDetails = new absl::flat_hash_map<
    kms_v1::CryptoKeyVersion_CryptoKeyVersionAlgorithm, const AlgorithmDetails>{

    // EC_SIGN_*
    {kms_v1::CryptoKeyVersion::EC_SIGN_P256_SHA256,
     AlgorithmDetails{
         kms_v1::CryptoKeyVersion::EC_SIGN_P256_SHA256,  // algorithm
         kms_v1::CryptoKey::ASYMMETRIC_SIGN,             // purpose
         {CKM_ECDSA},                                    // allowed_mechanisms
         CKK_EC,                                         // key_type
         256,                                            // key_size
         CKM_EC_KEY_PAIR_GEN,                            // key_gen_mechanism
         CKM_SHA256,                                     // digest_mechanism
     }},
    {kms_v1::CryptoKeyVersion::EC_SIGN_P384_SHA384,
     AlgorithmDetails{
         kms_v1::CryptoKeyVersion::EC_SIGN_P384_SHA384,  // algorithm
         kms_v1::CryptoKey::ASYMMETRIC_SIGN,             // purpose
         {CKM_ECDSA},                                    // allowed_mechanisms
         CKK_EC,                                         // key_type
         384,                                            // key_size
         CKM_EC_KEY_PAIR_GEN,                            // key_gen_mechanism
         CKM_SHA384,                                     // digest_mechanism
     }},

    // RSA_DECRYPT_OAEP_*
    {kms_v1::CryptoKeyVersion::RSA_DECRYPT_OAEP_2048_SHA256,
     AlgorithmDetails{
         kms_v1::CryptoKeyVersion::RSA_DECRYPT_OAEP_2048_SHA256,  // algorithm
         kms_v1::CryptoKey::ASYMMETRIC_DECRYPT,                   // purpose
         {CKM_RSA_PKCS_OAEP},        // allowed_mechanisms
         CKK_RSA,                    // key_type
         2048,                       // key_size
         CKM_RSA_PKCS_KEY_PAIR_GEN,  // key_gen_mechanism
         CKM_SHA256,                 // digest_mechanism
     }},
    {kms_v1::CryptoKeyVersion::RSA_DECRYPT_OAEP_3072_SHA256,
     AlgorithmDetails{
         kms_v1::CryptoKeyVersion::RSA_DECRYPT_OAEP_3072_SHA256,  // algorithm
         kms_v1::CryptoKey::ASYMMETRIC_DECRYPT,                   // purpose
         {CKM_RSA_PKCS_OAEP},        // allowed_mechanisms
         CKK_RSA,                    // key_type
         3072,                       // key_size
         CKM_RSA_PKCS_KEY_PAIR_GEN,  // key_gen_mechanism
         CKM_SHA256,                 // digest_mechanism
     }},
    {kms_v1::CryptoKeyVersion::RSA_DECRYPT_OAEP_4096_SHA256,
     AlgorithmDetails{
         kms_v1::CryptoKeyVersion::RSA_DECRYPT_OAEP_4096_SHA256,  // algorithm
         kms_v1::CryptoKey::ASYMMETRIC_DECRYPT,                   // purpose
         {CKM_RSA_PKCS_OAEP},        // allowed_mechanisms
         CKK_RSA,                    // key_type
         4096,                       // key_size
         CKM_RSA_PKCS_KEY_PAIR_GEN,  // key_gen_mechanism
         CKM_SHA256,                 // digest_mechanism
     }},
    {kms_v1::CryptoKeyVersion::RSA_DECRYPT_OAEP_4096_SHA512,
     AlgorithmDetails{
         kms_v1::CryptoKeyVersion::RSA_DECRYPT_OAEP_4096_SHA512,  // algorithm
         kms_v1::CryptoKey::ASYMMETRIC_DECRYPT,                   // purpose
         {CKM_RSA_PKCS_OAEP},        // allowed_mechanisms
         CKK_RSA,                    // key_type
         4096,                       // key_size
         CKM_RSA_PKCS_KEY_PAIR_GEN,  // key_gen_mechanism
         CKM_SHA512,                 // digest_mechanism
     }},

    // RSA_SIGN_PKCS1_*
    {kms_v1::CryptoKeyVersion::RSA_SIGN_PKCS1_2048_SHA256,
     AlgorithmDetails{
         kms_v1::CryptoKeyVersion::RSA_SIGN_PKCS1_2048_SHA256,  // algorithm
         kms_v1::CryptoKey::ASYMMETRIC_SIGN,                    // purpose
         {CKM_RSA_PKCS},             // allowed_mechanisms
         CKK_RSA,                    // key_type
         2048,                       // key_size
         CKM_RSA_PKCS_KEY_PAIR_GEN,  // key_gen_mechanism
         CKM_SHA256,                 // digest_mechanism
     }},
    {kms_v1::CryptoKeyVersion::RSA_SIGN_PKCS1_3072_SHA256,
     AlgorithmDetails{
         kms_v1::CryptoKeyVersion::RSA_SIGN_PKCS1_3072_SHA256,  // algorithm
         kms_v1::CryptoKey::ASYMMETRIC_SIGN,                    // purpose
         {CKM_RSA_PKCS},             // allowed_mechanisms
         CKK_RSA,                    // key_type
         3072,                       // key_size
         CKM_RSA_PKCS_KEY_PAIR_GEN,  // key_gen_mechanism
         CKM_SHA256,                 // digest_mechanism
     }},
    {kms_v1::CryptoKeyVersion::RSA_SIGN_PKCS1_4096_SHA256,
     AlgorithmDetails{
         kms_v1::CryptoKeyVersion::RSA_SIGN_PKCS1_4096_SHA256,  // algorithm
         kms_v1::CryptoKey::ASYMMETRIC_SIGN,                    // purpose
         {CKM_RSA_PKCS},             // allowed_mechanisms
         CKK_RSA,                    // key_type
         4096,                       // key_size
         CKM_RSA_PKCS_KEY_PAIR_GEN,  // key_gen_mechanism
         CKM_SHA256,                 // digest_mechanism
     }},
    {kms_v1::CryptoKeyVersion::RSA_SIGN_PKCS1_4096_SHA512,
     AlgorithmDetails{
         kms_v1::CryptoKeyVersion::RSA_SIGN_PKCS1_4096_SHA512,  // algorithm
         kms_v1::CryptoKey::ASYMMETRIC_SIGN,                    // purpose
         {CKM_RSA_PKCS},             // allowed_mechanisms
         CKK_RSA,                    // key_type
         4096,                       // key_size
         CKM_RSA_PKCS_KEY_PAIR_GEN,  // key_gen_mechanism
         CKM_SHA512,                 // digest_mechanism
     }},

    // RSA_SIGN_PSS_*
    {kms_v1::CryptoKeyVersion::RSA_SIGN_PSS_2048_SHA256,
     AlgorithmDetails{
         kms_v1::CryptoKeyVersion::RSA_SIGN_PSS_2048_SHA256,  // algorithm
         kms_v1::CryptoKey::ASYMMETRIC_SIGN,                  // purpose
         {CKM_RSA_PKCS_PSS},         // allowed_mechanisms
         CKK_RSA,                    // key_type
         2048,                       // key_size
         CKM_RSA_PKCS_KEY_PAIR_GEN,  // key_gen_mechanism
         CKM_SHA256,                 // digest_mechanism
     }},
    {kms_v1::CryptoKeyVersion::RSA_SIGN_PSS_3072_SHA256,
     AlgorithmDetails{
         kms_v1::CryptoKeyVersion::RSA_SIGN_PSS_3072_SHA256,  // algorithm
         kms_v1::CryptoKey::ASYMMETRIC_SIGN,                  // purpose
         {CKM_RSA_PKCS_PSS},         // allowed_mechanisms
         CKK_RSA,                    // key_type
         3072,                       // key_size
         CKM_RSA_PKCS_KEY_PAIR_GEN,  // key_gen_mechanism
         CKM_SHA256,                 // digest_mechanism
     }},
    {kms_v1::CryptoKeyVersion::RSA_SIGN_PSS_4096_SHA256,
     AlgorithmDetails{
         kms_v1::CryptoKeyVersion::RSA_SIGN_PSS_4096_SHA256,  // algorithm
         kms_v1::CryptoKey::ASYMMETRIC_SIGN,                  // purpose
         {CKM_RSA_PKCS_PSS},         // allowed_mechanisms
         CKK_RSA,                    // key_type
         4096,                       // key_size
         CKM_RSA_PKCS_KEY_PAIR_GEN,  // key_gen_mechanism
         CKM_SHA256,                 // digest_mechanism
     }},
    {kms_v1::CryptoKeyVersion::RSA_SIGN_PSS_4096_SHA512,
     AlgorithmDetails{
         kms_v1::CryptoKeyVersion::RSA_SIGN_PSS_4096_SHA512,  // algorithm
         kms_v1::CryptoKey::ASYMMETRIC_SIGN,                  // purpose
         {CKM_RSA_PKCS_PSS},         // allowed_mechanisms
         CKK_RSA,                    // key_type
         4096,                       // key_size
         CKM_RSA_PKCS_KEY_PAIR_GEN,  // key_gen_mechanism
         CKM_SHA512,                 // digest_mechanism
     }},

    // RSA_SIGN_RAW_PKCS1_*
    {kms_v1::CryptoKeyVersion::RSA_SIGN_RAW_PKCS1_2048,
     AlgorithmDetails{
         kms_v1::CryptoKeyVersion::RSA_SIGN_RAW_PKCS1_2048,  // algorithm
         kms_v1::CryptoKey::ASYMMETRIC_SIGN,                 // purpose
         {CKM_RSA_PKCS},             // allowed_mechanisms
         CKK_RSA,                    // key_type
         2048,                       // key_size
         CKM_RSA_PKCS_KEY_PAIR_GEN,  // key_gen_mechanism
         absl::nullopt,              // digest_mechanism
     }},
    {kms_v1::CryptoKeyVersion::RSA_SIGN_RAW_PKCS1_3072,
     AlgorithmDetails{
         kms_v1::CryptoKeyVersion::RSA_SIGN_RAW_PKCS1_3072,  // algorithm
         kms_v1::CryptoKey::ASYMMETRIC_SIGN,                 // purpose
         {CKM_RSA_PKCS},             // allowed_mechanisms
         CKK_RSA,                    // key_type
         3072,                       // key_size
         CKM_RSA_PKCS_KEY_PAIR_GEN,  // key_gen_mechanism
         absl::nullopt,              // digest_mechanism
     }},
    {kms_v1::CryptoKeyVersion::RSA_SIGN_RAW_PKCS1_4096,
     AlgorithmDetails{
         kms_v1::CryptoKeyVersion::RSA_SIGN_RAW_PKCS1_4096,  // algorithm
         kms_v1::CryptoKey::ASYMMETRIC_SIGN,                 // purpose
         {CKM_RSA_PKCS},             // allowed_mechanisms
         CKK_RSA,                    // key_type
         4096,                       // key_size
         CKM_RSA_PKCS_KEY_PAIR_GEN,  // key_gen_mechanism
         absl::nullopt,              // digest_mechanism
     }},
};

absl::StatusOr<AlgorithmDetails> GetDetails(
    kms_v1::CryptoKeyVersion::CryptoKeyVersionAlgorithm algorithm) {
  auto it = kAlgorithmDetails->find(algorithm);
  if (it == kAlgorithmDetails->end()) {
    return NewInternalError(
        absl::StrFormat("algorithm not found: %d", algorithm), SOURCE_LOCATION);
  }
  return it->second;
}

}  // namespace kmsp11
