package fakekms

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"

	kmspb "google.golang.org/genproto/googleapis/cloud/kms/v1"
)

// GetPublicKey fakes a Cloud KMS API function.
func (f *fakeKMS) GetPublicKey(ctx context.Context, req *kmspb.GetPublicKeyRequest) (*kmspb.PublicKey, error) {
	if err := allowlist("name").check(req); err != nil {
		return nil, err
	}

	name, err := parseCryptoKeyVersionName(req.Name)
	if err != nil {
		return nil, err
	}

	ckv, err := f.cryptoKeyVersion(name)
	if err != nil {
		return nil, err
	}

	if ckv.pb.State != kmspb.CryptoKeyVersion_ENABLED {
		return nil, errFailedPrecondition("key version %s is not enabled", name)
	}

	s, ok := ckv.keyMaterial.(crypto.Signer)
	if !ok {
		return nil, errFailedPrecondition("keys with algorithm %s do not contain a public key",
			nameForValue(kmspb.CryptoKeyVersion_CryptoKeyVersionAlgorithm_name, int32(ckv.pb.Algorithm)))
	}

	derPub, err := x509.MarshalPKIXPublicKey(s.Public())
	if err != nil {
		return nil, err
	}

	pemPub := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: derPub,
	})

	return &kmspb.PublicKey{
		Algorithm: ckv.pb.Algorithm,
		Pem:       string(pemPub),
	}, nil
}

// AsymmetricDecrypt fakes a Cloud KMS API function.
func (f *fakeKMS) AsymmetricDecrypt(ctx context.Context, req *kmspb.AsymmetricDecryptRequest) (*kmspb.AsymmetricDecryptResponse, error) {
	if err := allowlist("name", "ciphertext").check(req); err != nil {
		return nil, err
	}

	name, err := parseCryptoKeyVersionName(req.Name)
	if err != nil {
		return nil, err
	}

	ckv, err := f.cryptoKeyVersion(name)
	if err != nil {
		return nil, err
	}

	if ckv.pb.State != kmspb.CryptoKeyVersion_ENABLED {
		return nil, errFailedPrecondition("key version %s is not enabled", name)
	}

	def, _ := algorithmDef(ckv.pb.Algorithm)
	if def.Purpose != kmspb.CryptoKey_ASYMMETRIC_DECRYPT {
		return nil, errFailedPrecondition("keys with algorithm %s may not be used for asymmetric decryption",
			nameForValue(kmspb.CryptoKeyVersion_CryptoKeyVersionAlgorithm_name, int32(ckv.pb.Algorithm)))
	}

	pt, err := ckv.keyMaterial.(crypto.Decrypter).Decrypt(rand.Reader, req.Ciphertext, def.Opts)
	if err != nil {
		return nil, errInvalidArgument("decryption failed: %v", err)
	}

	return &kmspb.AsymmetricDecryptResponse{Plaintext: pt}, nil
}
