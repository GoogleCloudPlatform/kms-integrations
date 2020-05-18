package contract

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/asn1"
	"math/big"
	"testing"

	"oss-tools/kmsp11/test/fakekms/testutil"

	"github.com/google/go-cmp/cmp"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/testing/protocmp"

	kmspb "google.golang.org/genproto/googleapis/cloud/kms/v1"
	fmpb "google.golang.org/genproto/protobuf/field_mask"
)

var ignoreSignature = protocmp.IgnoreFields(new(kmspb.AsymmetricSignResponse), protoreflect.Name("signature"))

func TestECSign(t *testing.T) {
	ctx := context.Background()
	kr := client.CreateTestKR(ctx, t, &kmspb.CreateKeyRingRequest{Parent: location})
	ck := client.CreateTestCK(ctx, t, &kmspb.CreateCryptoKeyRequest{
		Parent: kr.Name,
		CryptoKey: &kmspb.CryptoKey{
			Purpose: kmspb.CryptoKey_ASYMMETRIC_SIGN,
			VersionTemplate: &kmspb.CryptoKeyVersionTemplate{
				Algorithm: kmspb.CryptoKeyVersion_EC_SIGN_P384_SHA384,
			},
		},
		SkipInitialVersionCreation: true,
	})
	ckv := client.CreateTestCKVAndWait(ctx, t, &kmspb.CreateCryptoKeyVersionRequest{
		Parent: ck.Name,
	})

	pubResp, err := client.GetPublicKey(ctx, &kmspb.GetPublicKeyRequest{
		Name: ckv.Name,
	})
	if err != nil {
		t.Fatal(err)
	}

	pub := unmarshalPublicKeyPem(t, pubResp.Pem).(*ecdsa.PublicKey)

	data := []byte("Here is some data to authenticate")
	digest := sha512.Sum384(data)

	got, err := client.AsymmetricSign(ctx, &kmspb.AsymmetricSignRequest{
		Name: ckv.Name,
		Digest: &kmspb.Digest{
			Digest: &kmspb.Digest_Sha384{
				Sha384: digest[:],
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	// Signature isn't predictable, but we want to compare to an empty message with
	// signature ignored so that the contract test breaks when KMS emits new fields.
	want := &kmspb.AsymmetricSignResponse{}

	opts := append(testutil.ProtoDiffOpts(), ignoreSignature)
	if diff := cmp.Diff(want, got, opts...); diff != "" {
		t.Errorf("proto mismatch (-want +got): %s", diff)
	}

	sig := struct{ R, S *big.Int }{}
	if _, err := asn1.Unmarshal(got.Signature, &sig); err != nil {
		t.Fatal(err)
	}

	if !ecdsa.Verify(pub, digest[:], sig.R, sig.S) {
		t.Error("signature verification failed")
	}
}

func TestRSASignPKCS1(t *testing.T) {
	ctx := context.Background()
	kr := client.CreateTestKR(ctx, t, &kmspb.CreateKeyRingRequest{Parent: location})
	ck := client.CreateTestCK(ctx, t, &kmspb.CreateCryptoKeyRequest{
		Parent: kr.Name,
		CryptoKey: &kmspb.CryptoKey{
			Purpose: kmspb.CryptoKey_ASYMMETRIC_SIGN,
			VersionTemplate: &kmspb.CryptoKeyVersionTemplate{
				Algorithm: kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_3072_SHA256,
			},
		},
		SkipInitialVersionCreation: true,
	})
	ckv := client.CreateTestCKVAndWait(ctx, t, &kmspb.CreateCryptoKeyVersionRequest{
		Parent: ck.Name,
	})

	pubResp, err := client.GetPublicKey(ctx, &kmspb.GetPublicKeyRequest{
		Name: ckv.Name,
	})
	if err != nil {
		t.Fatal(err)
	}

	pub := unmarshalPublicKeyPem(t, pubResp.Pem).(*rsa.PublicKey)

	data := []byte("Here is some data to authenticate")
	digest := sha256.Sum256(data)

	got, err := client.AsymmetricSign(ctx, &kmspb.AsymmetricSignRequest{
		Name: ckv.Name,
		Digest: &kmspb.Digest{
			Digest: &kmspb.Digest_Sha256{
				Sha256: digest[:],
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	// Signature isn't predictable, but we want to compare to an empty message with
	// signature ignored so that the contract test breaks when KMS emits new fields.
	want := &kmspb.AsymmetricSignResponse{}

	opts := append(testutil.ProtoDiffOpts(), ignoreSignature)
	if diff := cmp.Diff(want, got, opts...); diff != "" {
		t.Errorf("proto mismatch (-want +got): %s", diff)
	}

	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], got.Signature); err != nil {
		t.Error(err)
	}
}

func TestRSASignPSS(t *testing.T) {
	ctx := context.Background()
	kr := client.CreateTestKR(ctx, t, &kmspb.CreateKeyRingRequest{Parent: location})
	ck := client.CreateTestCK(ctx, t, &kmspb.CreateCryptoKeyRequest{
		Parent: kr.Name,
		CryptoKey: &kmspb.CryptoKey{
			Purpose: kmspb.CryptoKey_ASYMMETRIC_SIGN,
			VersionTemplate: &kmspb.CryptoKeyVersionTemplate{
				Algorithm: kmspb.CryptoKeyVersion_RSA_SIGN_PSS_4096_SHA512,
			},
		},
		SkipInitialVersionCreation: true,
	})
	ckv := client.CreateTestCKVAndWait(ctx, t, &kmspb.CreateCryptoKeyVersionRequest{
		Parent: ck.Name,
	})

	pubResp, err := client.GetPublicKey(ctx, &kmspb.GetPublicKeyRequest{
		Name: ckv.Name,
	})
	if err != nil {
		t.Fatal(err)
	}

	pub := unmarshalPublicKeyPem(t, pubResp.Pem).(*rsa.PublicKey)

	data := []byte("Here is some data to authenticate")
	digest := sha512.Sum512(data)

	got, err := client.AsymmetricSign(ctx, &kmspb.AsymmetricSignRequest{
		Name: ckv.Name,
		Digest: &kmspb.Digest{
			Digest: &kmspb.Digest_Sha512{
				Sha512: digest[:],
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	// Signature isn't predictable, but we want to compare to an empty message with
	// signature ignored so that the contract test breaks when KMS emits new fields.
	want := &kmspb.AsymmetricSignResponse{}

	opts := append(testutil.ProtoDiffOpts(), ignoreSignature)
	if diff := cmp.Diff(want, got, opts...); diff != "" {
		t.Errorf("proto mismatch (-want +got): %s", diff)
	}

	pssOpts := &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash}
	if err := rsa.VerifyPSS(pub, crypto.SHA512, digest[:], got.Signature, pssOpts); err != nil {
		t.Error(err)
	}
}

func TestAsymmetricSignMalformedName(t *testing.T) {
	ctx := context.Background()

	_, err := client.AsymmetricSign(ctx, &kmspb.AsymmetricSignRequest{
		Name: "malformed name",
	})
	if status.Code(err) != codes.InvalidArgument {
		t.Errorf("err=%v, want code=%s", err, codes.InvalidArgument)
	}
}

func TestAsymmetricSignWrongDigest(t *testing.T) {
	ctx := context.Background()
	kr := client.CreateTestKR(ctx, t, &kmspb.CreateKeyRingRequest{Parent: location})
	ck := client.CreateTestCK(ctx, t, &kmspb.CreateCryptoKeyRequest{
		Parent: kr.Name,
		CryptoKey: &kmspb.CryptoKey{
			Purpose: kmspb.CryptoKey_ASYMMETRIC_SIGN,
			VersionTemplate: &kmspb.CryptoKeyVersionTemplate{
				Algorithm: kmspb.CryptoKeyVersion_EC_SIGN_P384_SHA384,
			},
		},
		SkipInitialVersionCreation: true,
	})
	ckv := client.CreateTestCKVAndWait(ctx, t, &kmspb.CreateCryptoKeyVersionRequest{
		Parent: ck.Name,
	})

	digest := sha256.Sum256([]byte("here is some data"))

	_, err := client.AsymmetricSign(ctx, &kmspb.AsymmetricSignRequest{
		Name: ckv.Name,
		Digest: &kmspb.Digest{
			Digest: &kmspb.Digest_Sha256{
				Sha256: digest[:],
			},
		},
	})
	if status.Code(err) != codes.InvalidArgument {
		t.Errorf("err=%v, want code=%s", err, codes.InvalidArgument)
	}
}

func TestAsymmetricSignIncorrectDigestLength(t *testing.T) {
	ctx := context.Background()
	kr := client.CreateTestKR(ctx, t, &kmspb.CreateKeyRingRequest{Parent: location})
	ck := client.CreateTestCK(ctx, t, &kmspb.CreateCryptoKeyRequest{
		Parent: kr.Name,
		CryptoKey: &kmspb.CryptoKey{
			Purpose: kmspb.CryptoKey_ASYMMETRIC_SIGN,
			VersionTemplate: &kmspb.CryptoKeyVersionTemplate{
				Algorithm: kmspb.CryptoKeyVersion_EC_SIGN_P384_SHA384,
			},
		},
		SkipInitialVersionCreation: true,
	})
	ckv := client.CreateTestCKVAndWait(ctx, t, &kmspb.CreateCryptoKeyVersionRequest{
		Parent: ck.Name,
	})

	digest := sha256.Sum256([]byte("here is some data"))

	_, err := client.AsymmetricSign(ctx, &kmspb.AsymmetricSignRequest{
		Name: ckv.Name,
		Digest: &kmspb.Digest{
			Digest: &kmspb.Digest_Sha384{
				Sha384: digest[:],
			},
		},
	})
	if status.Code(err) != codes.InvalidArgument {
		t.Errorf("err=%v, want code=%s", err, codes.InvalidArgument)
	}
}

func TestAsymmetricSignNotFound(t *testing.T) {
	ctx := context.Background()

	_, err := client.AsymmetricSign(ctx, &kmspb.AsymmetricSignRequest{
		Name: location + "/keyRings/foo/cryptoKeys/bar/cryptoKeyVersions/1",
	})
	if status.Code(err) != codes.NotFound {
		t.Errorf("err=%v, want code=%s", err, codes.NotFound)
	}
}

func TestAsymmetricSignWrongPurpose(t *testing.T) {
	ctx := context.Background()
	kr := client.CreateTestKR(ctx, t, &kmspb.CreateKeyRingRequest{Parent: location})
	ck := client.CreateTestCK(ctx, t, &kmspb.CreateCryptoKeyRequest{
		Parent: kr.Name,
		CryptoKey: &kmspb.CryptoKey{
			Purpose: kmspb.CryptoKey_ENCRYPT_DECRYPT,
		},
	})

	digest := sha256.Sum256([]byte("here is some data"))

	_, err := client.AsymmetricSign(ctx, &kmspb.AsymmetricSignRequest{
		Name: ck.Primary.Name,
		Digest: &kmspb.Digest{
			Digest: &kmspb.Digest_Sha256{
				Sha256: digest[:],
			},
		},
	})
	if status.Code(err) != codes.FailedPrecondition {
		t.Errorf("err=%v, want code=%s", err, codes.FailedPrecondition)
	}
}

func TestAsymmetricSignDisabled(t *testing.T) {
	ctx := context.Background()
	kr := client.CreateTestKR(ctx, t, &kmspb.CreateKeyRingRequest{Parent: location})
	ck := client.CreateTestCK(ctx, t, &kmspb.CreateCryptoKeyRequest{
		Parent: kr.Name,
		CryptoKey: &kmspb.CryptoKey{
			Purpose: kmspb.CryptoKey_ASYMMETRIC_SIGN,
			VersionTemplate: &kmspb.CryptoKeyVersionTemplate{
				Algorithm: kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256,
			},
		},
		SkipInitialVersionCreation: true,
	})
	ckv := client.CreateTestCKVAndWait(ctx, t, &kmspb.CreateCryptoKeyVersionRequest{
		Parent: ck.Name,
	})

	ckv.State = kmspb.CryptoKeyVersion_DISABLED

	_, err := client.UpdateCryptoKeyVersion(ctx, &kmspb.UpdateCryptoKeyVersionRequest{
		CryptoKeyVersion: ckv,
		UpdateMask:       &fmpb.FieldMask{Paths: []string{"state"}},
	})
	if err != nil {
		t.Fatal(err)
	}

	_, err = client.AsymmetricSign(ctx, &kmspb.AsymmetricSignRequest{
		Name: ckv.Name,
	})
	if status.Code(err) != codes.FailedPrecondition {
		t.Errorf("err=%v, want code=%s", err, codes.FailedPrecondition)
	}
}
