package fakekms

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"hash/crc32"

	kmspb "google.golang.org/genproto/googleapis/cloud/kms/v1"
	wrapperspb "google.golang.org/protobuf/types/known/wrapperspb"
)

var crc32cTable = crc32.MakeTable(crc32.Castagnoli)

func crc32c(data []byte) *wrapperspb.Int64Value {
	return wrapperspb.Int64(int64(crc32.Checksum(data, crc32cTable)))
}

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
		Name:      req.Name,
		Algorithm: ckv.pb.Algorithm,
		Pem:       string(pemPub),
		PemCrc32C: crc32c(pemPub),
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

	return &kmspb.AsymmetricDecryptResponse{
		Plaintext:       pt,
		PlaintextCrc32C: crc32c(pt),
	}, nil
}

// AsymmetricSign fakes a Cloud KMS API function.
func (f *fakeKMS) AsymmetricSign(ctx context.Context, req *kmspb.AsymmetricSignRequest) (*kmspb.AsymmetricSignResponse, error) {
	if err := allowlist("name", "data", "digest.sha256", "digest.sha384", "digest.sha512").check(req); err != nil {
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
	if def.Purpose != kmspb.CryptoKey_ASYMMETRIC_SIGN {
		return nil, errFailedPrecondition("keys with algorithm %s may not be used for signing",
			nameForValue(kmspb.CryptoKeyVersion_CryptoKeyVersionAlgorithm_name, int32(ckv.pb.Algorithm)))
	}

	opts := def.Opts.(crypto.SignerOpts)

	var data []byte
	if opts.HashFunc() == crypto.Hash(0) {
		data = req.Data
	} else {
		switch opts.HashFunc() {
		case crypto.SHA256:
			data = req.Digest.GetSha256()
		case crypto.SHA384:
			data = req.Digest.GetSha384()
		case crypto.SHA512:
			data = req.Digest.GetSha512()
		default:
			return nil, errInternal("unsupported hash: %d", opts.HashFunc())
		}

		if len(data) != opts.HashFunc().Size() {
			return nil, errInvalidArgument("len(digest)=%d, want %d", len(data), opts.HashFunc().Size())
		}
	}

	sig, err := ckv.keyMaterial.(crypto.Signer).Sign(rand.Reader, data, opts)
	if err != nil {
		return nil, errInternal("signing failed: %v", err)
	}

	return &kmspb.AsymmetricSignResponse{
		// Not yet emitted (cl/342265843)
		// Name:            req.Name,
		Signature:       sig,
		SignatureCrc32C: crc32c(sig),
	}, nil
}
