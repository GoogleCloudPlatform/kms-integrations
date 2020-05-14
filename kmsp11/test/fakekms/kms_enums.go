package fakekms

import (
	"fmt"

	kmspb "google.golang.org/genproto/googleapis/cloud/kms/v1"
)

// AlgorithmToPurpose maps supported KMS algorithms to their defined purposes.
var algorithmToPurpose = map[kmspb.CryptoKeyVersion_CryptoKeyVersionAlgorithm]kmspb.CryptoKey_CryptoKeyPurpose{
	// ENCRYPT_DECRYPT
	kmspb.CryptoKeyVersion_GOOGLE_SYMMETRIC_ENCRYPTION: kmspb.CryptoKey_ENCRYPT_DECRYPT,

	// ASYMMETRIC_DECRYPT
	kmspb.CryptoKeyVersion_RSA_DECRYPT_OAEP_2048_SHA256: kmspb.CryptoKey_ASYMMETRIC_DECRYPT,
	kmspb.CryptoKeyVersion_RSA_DECRYPT_OAEP_3072_SHA256: kmspb.CryptoKey_ASYMMETRIC_DECRYPT,
	kmspb.CryptoKeyVersion_RSA_DECRYPT_OAEP_4096_SHA256: kmspb.CryptoKey_ASYMMETRIC_DECRYPT,
	kmspb.CryptoKeyVersion_RSA_DECRYPT_OAEP_4096_SHA512: kmspb.CryptoKey_ASYMMETRIC_DECRYPT,

	// ASYMMETRIC_SIGN
	kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256: kmspb.CryptoKey_ASYMMETRIC_SIGN,
	kmspb.CryptoKeyVersion_EC_SIGN_P384_SHA384: kmspb.CryptoKey_ASYMMETRIC_SIGN,

	kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_2048_SHA256: kmspb.CryptoKey_ASYMMETRIC_SIGN,
	kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_3072_SHA256: kmspb.CryptoKey_ASYMMETRIC_SIGN,
	kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_4096_SHA256: kmspb.CryptoKey_ASYMMETRIC_SIGN,
	kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_4096_SHA512: kmspb.CryptoKey_ASYMMETRIC_SIGN,

	kmspb.CryptoKeyVersion_RSA_SIGN_PSS_2048_SHA256: kmspb.CryptoKey_ASYMMETRIC_SIGN,
	kmspb.CryptoKeyVersion_RSA_SIGN_PSS_3072_SHA256: kmspb.CryptoKey_ASYMMETRIC_SIGN,
	kmspb.CryptoKeyVersion_RSA_SIGN_PSS_4096_SHA256: kmspb.CryptoKey_ASYMMETRIC_SIGN,
	kmspb.CryptoKeyVersion_RSA_SIGN_PSS_4096_SHA512: kmspb.CryptoKey_ASYMMETRIC_SIGN,
}

var purposes map[kmspb.CryptoKey_CryptoKeyPurpose]struct{}

func init() { // fill purposes from algorithmToPurpose values
	purposes = make(map[kmspb.CryptoKey_CryptoKeyPurpose]struct{})
	for _, p := range algorithmToPurpose {
		purposes[p] = struct{}{}
	}
}

// nameForValue retrieves the mapped name corresponding to value, or a string representation
// of the numeric value if the value is unknown.
func nameForValue(names map[int32]string, value int32) string {
	if name, ok := names[value]; ok {
		return name
	}
	return fmt.Sprintf("%d", value)
}

// validatePurpose returns nil on success, or Unimplemented if the supplied purpose is not
// supported. Note that CRYPTO_KEY_PURPOSE_UNSPECIFIED is not a supported purpose.
func validatePurpose(purpose kmspb.CryptoKey_CryptoKeyPurpose) error {
	if _, ok := purposes[purpose]; !ok {
		return errUnimplemented("unsupported purpose: %s",
			nameForValue(kmspb.CryptoKey_CryptoKeyPurpose_name, int32(purpose)))
	}
	return nil
}

// validateProtectionLevel returns nil on success, or Unimplemented if the supplied protection
// level is not supported. Note that PROTECTION_LEVEL_UNSPECIFIED is not a supported level.
func validateProtectionLevel(pl kmspb.ProtectionLevel) error {
	switch pl {
	case kmspb.ProtectionLevel_SOFTWARE, kmspb.ProtectionLevel_HSM:
		return nil
	default:
		return errUnimplemented("unsupported protection level: %s",
			nameForValue(kmspb.ProtectionLevel_name, int32(pl)))
	}
}

// validateAlgorithm returns nil on success, Unimplemented if the supplied algorithm is not
// supported, or InvalidArgument if the algorithm is inconsistent with the supplied purpose.
// Note that CRYPTO_KEY_VERSION_ALGORITHM_UNSPECIFIED is not a supported algorithm.
func validateAlgorithm(alg kmspb.CryptoKeyVersion_CryptoKeyVersionAlgorithm, purpose kmspb.CryptoKey_CryptoKeyPurpose) error {
	gotPurpose, ok := algorithmToPurpose[alg]
	if !ok {
		return errUnimplemented("unsupported algorithm: %s",
			nameForValue(kmspb.CryptoKeyVersion_CryptoKeyVersionAlgorithm_name, int32(alg)))
	}
	if purpose != gotPurpose {
		return errInvalidArgument("algorithm %s is not valid for purpose %s",
			nameForValue(kmspb.CryptoKeyVersion_CryptoKeyVersionAlgorithm_name, int32(alg)),
			nameForValue(kmspb.CryptoKey_CryptoKeyPurpose_name, int32(purpose)))
	}
	return nil
}
