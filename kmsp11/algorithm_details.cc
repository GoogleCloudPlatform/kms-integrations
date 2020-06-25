#include "kmsp11/algorithm_details.h"

#include "absl/container/flat_hash_map.h"
#include "kmsp11/util/errors.h"

namespace kmsp11 {

#define KMS_ALGORITHM(name) \
  kms_v1::CryptoKeyVersion_CryptoKeyVersionAlgorithm_##name
#define KMS_PURPOSE(name) kms_v1::CryptoKey_CryptoKeyPurpose_##name

static const auto* kAlgorithmDetails =
    new absl::flat_hash_map<kms_v1::CryptoKeyVersion_CryptoKeyVersionAlgorithm,
                            AlgorithmDetails>{

        // EC_SIGN_*
        {KMS_ALGORITHM(EC_SIGN_P256_SHA256),
         AlgorithmDetails{
             KMS_ALGORITHM(EC_SIGN_P256_SHA256),  // algorithm
             KMS_PURPOSE(ASYMMETRIC_SIGN),        // purpose
             {CKM_ECDSA},                         // allowed_mechanisms
             CKK_EC,                              // key_type
             256,                                 // key_size
             CKM_EC_KEY_PAIR_GEN,                 // key_gen_mechanism
             CKM_SHA256,                          // digest_mechanism
             EVP_sha256(),                        // digest
         }},
        {KMS_ALGORITHM(EC_SIGN_P384_SHA384),
         AlgorithmDetails{
             KMS_ALGORITHM(EC_SIGN_P384_SHA384),  // algorithm
             KMS_PURPOSE(ASYMMETRIC_SIGN),        // purpose
             {CKM_ECDSA},                         // allowed_mechanisms
             CKK_EC,                              // key_type
             384,                                 // key_size
             CKM_EC_KEY_PAIR_GEN,                 // key_gen_mechanism
             CKM_SHA384,                          // digest_mechanism
             EVP_sha384(),                        // digest
         }},

        // RSA_DECRYPT_OAEP_*
        {KMS_ALGORITHM(RSA_DECRYPT_OAEP_2048_SHA256),
         AlgorithmDetails{
             KMS_ALGORITHM(RSA_DECRYPT_OAEP_2048_SHA256),  // algorithm
             KMS_PURPOSE(ASYMMETRIC_DECRYPT),              // purpose
             {CKM_RSA_PKCS_OAEP},                          // allowed_mechanisms
             CKK_RSA,                                      // key_type
             2048,                                         // key_size
             CKM_RSA_PKCS_KEY_PAIR_GEN,                    // key_gen_mechanism
             CKM_SHA256,                                   // digest_mechanism
             EVP_sha256(),                                 // digest
         }},
        {KMS_ALGORITHM(RSA_DECRYPT_OAEP_3072_SHA256),
         AlgorithmDetails{
             KMS_ALGORITHM(RSA_DECRYPT_OAEP_3072_SHA256),  // algorithm
             KMS_PURPOSE(ASYMMETRIC_DECRYPT),              // purpose
             {CKM_RSA_PKCS_OAEP},                          // allowed_mechanisms
             CKK_RSA,                                      // key_type
             3072,                                         // key_size
             CKM_RSA_PKCS_KEY_PAIR_GEN,                    // key_gen_mechanism
             CKM_SHA256,                                   // digest_mechanism
             EVP_sha256(),                                 // digest
         }},
        {KMS_ALGORITHM(RSA_DECRYPT_OAEP_4096_SHA256),
         AlgorithmDetails{
             KMS_ALGORITHM(RSA_DECRYPT_OAEP_4096_SHA256),  // algorithm
             KMS_PURPOSE(ASYMMETRIC_DECRYPT),              // purpose
             {CKM_RSA_PKCS_OAEP},                          // allowed_mechanisms
             CKK_RSA,                                      // key_type
             4096,                                         // key_size
             CKM_RSA_PKCS_KEY_PAIR_GEN,                    // key_gen_mechanism
             CKM_SHA256,                                   // digest_mechanism
             EVP_sha256(),                                 // digest
         }},
        {KMS_ALGORITHM(RSA_DECRYPT_OAEP_4096_SHA512),
         AlgorithmDetails{
             KMS_ALGORITHM(RSA_DECRYPT_OAEP_4096_SHA512),  // algorithm
             KMS_PURPOSE(ASYMMETRIC_DECRYPT),              // purpose
             {CKM_RSA_PKCS_OAEP},                          // allowed_mechanisms
             CKK_RSA,                                      // key_type
             4096,                                         // key_size
             CKM_RSA_PKCS_KEY_PAIR_GEN,                    // key_gen_mechanism
             CKM_SHA512,                                   // digest_mechanism
             EVP_sha512(),                                 // digest
         }},

        // RSA_SIGN_PKCS1_*
        {KMS_ALGORITHM(RSA_SIGN_PKCS1_2048_SHA256),
         AlgorithmDetails{
             KMS_ALGORITHM(RSA_SIGN_PKCS1_2048_SHA256),  // algorithm
             KMS_PURPOSE(ASYMMETRIC_SIGN),               // purpose
             {CKM_RSA_PKCS},                             // allowed_mechanisms
             CKK_RSA,                                    // key_type
             2048,                                       // key_size
             CKM_RSA_PKCS_KEY_PAIR_GEN,                  // key_gen_mechanism
             CKM_SHA256,                                 // digest_mechanism
             EVP_sha256(),                               // digest
         }},
        {KMS_ALGORITHM(RSA_SIGN_PKCS1_3072_SHA256),
         AlgorithmDetails{
             KMS_ALGORITHM(RSA_SIGN_PKCS1_3072_SHA256),  // algorithm
             KMS_PURPOSE(ASYMMETRIC_SIGN),               // purpose
             {CKM_RSA_PKCS},                             // allowed_mechanisms
             CKK_RSA,                                    // key_type
             3072,                                       // key_size
             CKM_RSA_PKCS_KEY_PAIR_GEN,                  // key_gen_mechanism
             CKM_SHA256,                                 // digest_mechanism
             EVP_sha256(),                               // digest
         }},
        {KMS_ALGORITHM(RSA_SIGN_PKCS1_4096_SHA256),
         AlgorithmDetails{
             KMS_ALGORITHM(RSA_SIGN_PKCS1_4096_SHA256),  // algorithm
             KMS_PURPOSE(ASYMMETRIC_SIGN),               // purpose
             {CKM_RSA_PKCS},                             // allowed_mechanisms
             CKK_RSA,                                    // key_type
             4096,                                       // key_size
             CKM_RSA_PKCS_KEY_PAIR_GEN,                  // key_gen_mechanism
             CKM_SHA256,                                 // digest_mechanism
             EVP_sha256(),                               // digest
         }},
        {KMS_ALGORITHM(RSA_SIGN_PKCS1_4096_SHA512),
         AlgorithmDetails{
             KMS_ALGORITHM(RSA_SIGN_PKCS1_4096_SHA512),  // algorithm
             KMS_PURPOSE(ASYMMETRIC_SIGN),               // purpose
             {CKM_RSA_PKCS},                             // allowed_mechanisms
             CKK_RSA,                                    // key_type
             4096,                                       // key_size
             CKM_RSA_PKCS_KEY_PAIR_GEN,                  // key_gen_mechanism
             CKM_SHA512,                                 // digest_mechanism
             EVP_sha512(),                               // digest
         }},

        // RSA_SIGN_PSS_*
        {KMS_ALGORITHM(RSA_SIGN_PSS_2048_SHA256),
         AlgorithmDetails{
             KMS_ALGORITHM(RSA_SIGN_PSS_2048_SHA256),  // algorithm
             KMS_PURPOSE(ASYMMETRIC_SIGN),             // purpose
             {CKM_RSA_PKCS_PSS},                       // allowed_mechanisms
             CKK_RSA,                                  // key_type
             2048,                                     // key_size
             CKM_RSA_PKCS_KEY_PAIR_GEN,                // key_gen_mechanism
             CKM_SHA256,                               // digest_mechanism
             EVP_sha256(),                             // digest
         }},
        {KMS_ALGORITHM(RSA_SIGN_PSS_3072_SHA256),
         AlgorithmDetails{
             KMS_ALGORITHM(RSA_SIGN_PSS_3072_SHA256),  // algorithm
             KMS_PURPOSE(ASYMMETRIC_SIGN),             // purpose
             {CKM_RSA_PKCS_PSS},                       // allowed_mechanisms
             CKK_RSA,                                  // key_type
             3072,                                     // key_size
             CKM_RSA_PKCS_KEY_PAIR_GEN,                // key_gen_mechanism
             CKM_SHA256,                               // digest_mechanism
             EVP_sha256(),                             // digest
         }},
        {KMS_ALGORITHM(RSA_SIGN_PSS_4096_SHA256),
         AlgorithmDetails{
             KMS_ALGORITHM(RSA_SIGN_PSS_4096_SHA256),  // algorithm
             KMS_PURPOSE(ASYMMETRIC_SIGN),             // purpose
             {CKM_RSA_PKCS_PSS},                       // allowed_mechanisms
             CKK_RSA,                                  // key_type
             4096,                                     // key_size
             CKM_RSA_PKCS_KEY_PAIR_GEN,                // key_gen_mechanism
             CKM_SHA256,                               // digest_mechanism
             EVP_sha256(),                             // digest
         }},
        {KMS_ALGORITHM(RSA_SIGN_PSS_4096_SHA512),
         AlgorithmDetails{
             KMS_ALGORITHM(RSA_SIGN_PSS_4096_SHA512),  // algorithm
             KMS_PURPOSE(ASYMMETRIC_SIGN),             // purpose
             {CKM_RSA_PKCS_PSS},                       // allowed_mechanisms
             CKK_RSA,                                  // key_type
             4096,                                     // key_size
             CKM_RSA_PKCS_KEY_PAIR_GEN,                // key_gen_mechanism
             CKM_SHA512,                               // digest_mechanism
             EVP_sha512(),                             // digest
         }},
    };

StatusOr<AlgorithmDetails> GetDetails(
    kms_v1::CryptoKeyVersion::CryptoKeyVersionAlgorithm algorithm) {
  auto it = kAlgorithmDetails->find(algorithm);
  if (it == kAlgorithmDetails->end()) {
    return NewInternalError(
        absl::StrFormat("algorithm not found: %d", algorithm), SOURCE_LOCATION);
  }
  return it->second;
}

}  // namespace kmsp11
