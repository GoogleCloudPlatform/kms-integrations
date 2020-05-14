package fakekms

import (
	"context"

	"github.com/golang/protobuf/ptypes"

	kmspb "google.golang.org/genproto/googleapis/cloud/kms/v1"
)

// CreateCryptoKey fakes a Cloud KMS API function.
func (f *fakeKMS) CreateCryptoKey(ctx context.Context, req *kmspb.CreateCryptoKeyRequest) (*kmspb.CryptoKey, error) {
	// TODO(bdhess): revisit handling of output-only fields (http://g/api-discuss/vUowIGKPFT4)
	if err := whitelist("parent", "crypto_key_id", "skip_initial_version_creation",
		"crypto_key.purpose", "crypto_key.version_template.algorithm",
		"crypto_key.version_template.protection_level").check(req); err != nil {
		return nil, err
	}

	if !req.SkipInitialVersionCreation {
		return nil, errUnimplemented("creating versions is not yet supported")
	}

	krName, err := parseKeyRingName(req.Parent)
	if err != nil {
		return nil, err
	}
	if err := checkID(req.CryptoKeyId); err != nil {
		return nil, err
	}
	name := cryptoKeyName{keyRingName: krName, CryptoKeyID: req.CryptoKeyId}

	purpose := req.GetCryptoKey().GetPurpose()
	if purpose == kmspb.CryptoKey_CRYPTO_KEY_PURPOSE_UNSPECIFIED {
		return nil, errRequiredField("crypto_key.purpose")
	}
	if err := validatePurpose(purpose); err != nil {
		return nil, err
	}

	alg := req.GetCryptoKey().GetVersionTemplate().GetAlgorithm()
	if alg == kmspb.CryptoKeyVersion_CRYPTO_KEY_VERSION_ALGORITHM_UNSPECIFIED {
		alg = kmspb.CryptoKeyVersion_GOOGLE_SYMMETRIC_ENCRYPTION
	}
	if err := validateAlgorithm(alg, purpose); err != nil {
		return nil, err
	}

	protLevel := req.GetCryptoKey().GetVersionTemplate().GetProtectionLevel()
	if protLevel == kmspb.ProtectionLevel_PROTECTION_LEVEL_UNSPECIFIED {
		protLevel = kmspb.ProtectionLevel_SOFTWARE
	}
	if err := validateProtectionLevel(protLevel); err != nil {
		return nil, err
	}

	kr, ok := f.keyRings[krName]
	if !ok {
		return nil, errNotFound(krName)
	}
	if _, ok := kr.keys[name]; ok {
		return nil, errAlreadyExists(name)
	}

	pb := &kmspb.CryptoKey{
		Name:       name.String(),
		CreateTime: ptypes.TimestampNow(),
		Purpose:    purpose,
		VersionTemplate: &kmspb.CryptoKeyVersionTemplate{
			ProtectionLevel: protLevel,
			Algorithm:       alg,
		},
	}
	kr.keys[name] = &cryptoKey{pb: pb}
	return pb, nil
}
