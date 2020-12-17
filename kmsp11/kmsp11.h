#ifndef KMSP11_KMSP11_H_
#define KMSP11_KMSP11_H_

#ifdef __cplusplus
extern "C" {
#endif

// A marker for a PKCS #11 attribute or flag defined by Google.
// (Note that 0x80000000UL is CKA_VENDOR_DEFINED).
#define CKA_GOOGLE_DEFINED (0x80000000UL | 0x1E100UL)

// An attribute that indicates the backing CryptoKeyVersionAlgorithm in Cloud
// KMS.
#define CKA_KMS_ALGORITHM (CKA_GOOGLE_DEFINED | 0x01UL)

// ECDSA on the NIST P-256 curve with a SHA256 digest.
#define KMS_ALGORITHM_EC_SIGN_P256_SHA256 12UL
// ECDSA on the NIST P-384 curve with a SHA384 digest.
#define KMS_ALGORITHM_EC_SIGN_P384_SHA384 13UL

// RSAES-OAEP with a 2048 bit key and a SHA256 digest.
#define KMS_ALGORITHM_RSA_DECRYPT_OAEP_2048_SHA256 8UL
// RSAES-OAEP with a 3072 bit key and a SHA256 digest.
#define KMS_ALGORITHM_RSA_DECRYPT_OAEP_3072_SHA256 9UL
// RSAES-OAEP with a 4096 bit key and a SHA256 digest.
#define KMS_ALGORITHM_RSA_DECRYPT_OAEP_4096_SHA256 10UL
// RSAES-OAEP with a 4096 bit key and a SHA512 digest.
#define KMS_ALGORITHM_RSA_DECRYPT_OAEP_4096_SHA512 17UL

// RSASSA-PKCS1-v1_5 with a 2048 bit key and a SHA256 digest.
#define KMS_ALGORITHM_RSA_SIGN_PKCS1_2048_SHA256 5UL
// RSASSA-PKCS1-v1_5 with a 3072 bit key and a SHA256 digest.
#define KMS_ALGORITHM_RSA_SIGN_PKCS1_3072_SHA256 6UL
// RSASSA-PKCS1-v1_5 with a 4096 bit key and a SHA256 digest.
#define KMS_ALGORITHM_RSA_SIGN_PKCS1_4096_SHA256 7UL
// RSASSA-PKCS1-v1_5 with a 4096 bit key and a SHA512 digest.
#define KMS_ALGORITHM_RSA_SIGN_PKCS1_4096_SHA512 16UL

// RSASSA-PSS with a 2048 bit key and a SHA256 digest.
#define KMS_ALGORITHM_RSA_SIGN_PSS_2048_SHA256 2UL
// RSASSA-PSS with a 3072 bit key and a SHA256 digest.
#define KMS_ALGORITHM_RSA_SIGN_PSS_3072_SHA256 3UL
// RSASSA-PSS with a 4096 bit key and a SHA256 digest.
#define KMS_ALGORITHM_RSA_SIGN_PSS_4096_SHA256 4UL
// RSASSA-PSS with a 4096 bit key and a SHA512 digest.
#define KMS_ALGORITHM_RSA_SIGN_PSS_4096_SHA512 15UL

// RSASSA-PKCS1-v1_5 signing without encoding, with a 2048 bit key.
#define KMS_ALGORITHM_RSA_SIGN_RAW_PKCS1_2048 28UL
// RSASSA-PKCS1-v1_5 signing without encoding, with a 3072 bit key.
#define KMS_ALGORITHM_RSA_SIGN_RAW_PKCS1_3072 29UL
// RSASSA-PKCS1-v1_5 signing without encoding, with a 4096 bit key.
#define KMS_ALGORITHM_RSA_SIGN_RAW_PKCS1_4096 30UL

#ifdef __cplusplus
}
#endif

#endif  // KMSP11_KMSP11_H_
