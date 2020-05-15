package contract

import (
	"context"
	"fmt"
	"testing"

	"oss-tools/kmsp11/test/fakekms/testutil"

	"github.com/golang/protobuf/ptypes"
	"github.com/google/go-cmp/cmp"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	kmspb "google.golang.org/genproto/googleapis/cloud/kms/v1"
)

func TestCreateCryptoKeyDefaults(t *testing.T) {
	ctx := context.Background()

	kr, err := client.CreateKeyRing(ctx, &kmspb.CreateKeyRingRequest{
		Parent:    location,
		KeyRingId: testutil.RandomID(t),
	})
	if err != nil {
		t.Fatal(err)
	}

	got, err := client.CreateCryptoKey(ctx, &kmspb.CreateCryptoKeyRequest{
		Parent:      kr.Name,
		CryptoKeyId: "encrypt",
		CryptoKey: &kmspb.CryptoKey{
			Purpose: kmspb.CryptoKey_ENCRYPT_DECRYPT,
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	want := kmspb.CryptoKey{
		Name:       kr.Name + "/cryptoKeys/encrypt",
		CreateTime: ptypes.TimestampNow(),
		Purpose:    kmspb.CryptoKey_ENCRYPT_DECRYPT,
		VersionTemplate: &kmspb.CryptoKeyVersionTemplate{
			ProtectionLevel: kmspb.ProtectionLevel_SOFTWARE,
			Algorithm:       kmspb.CryptoKeyVersion_GOOGLE_SYMMETRIC_ENCRYPTION,
		},
		Primary: &kmspb.CryptoKeyVersion{
			Name:            kr.Name + "/cryptoKeys/encrypt/cryptoKeyVersions/1",
			CreateTime:      ptypes.TimestampNow(),
			GenerateTime:    ptypes.TimestampNow(),
			Algorithm:       kmspb.CryptoKeyVersion_GOOGLE_SYMMETRIC_ENCRYPTION,
			ProtectionLevel: kmspb.ProtectionLevel_SOFTWARE,
			State:           kmspb.CryptoKeyVersion_ENABLED,
		},
	}

	if diff := cmp.Diff(want, got, testutil.ProtoDiffOpts()...); diff != "" {
		t.Errorf("unexpected diff (-want, +got): %s", diff)
	}
}

func TestCreateCryptoKeyAlgorithms(t *testing.T) {
	ctx := context.Background()

	kr, err := client.CreateKeyRing(ctx, &kmspb.CreateKeyRingRequest{
		Parent:    location,
		KeyRingId: testutil.RandomID(t),
	})
	if err != nil {
		t.Fatal(err)
	}

	var cases = []struct {
		Name            string
		Purpose         kmspb.CryptoKey_CryptoKeyPurpose
		Algorithm       kmspb.CryptoKeyVersion_CryptoKeyVersionAlgorithm
		ProtectionLevel kmspb.ProtectionLevel
	}{
		{
			Name:            "ENCRYPT_DECRYPT_SOFTWARE",
			Purpose:         kmspb.CryptoKey_ENCRYPT_DECRYPT,
			Algorithm:       kmspb.CryptoKeyVersion_GOOGLE_SYMMETRIC_ENCRYPTION,
			ProtectionLevel: kmspb.ProtectionLevel_SOFTWARE,
		},
		{
			Name:            "SIGN_P256_HSM",
			Purpose:         kmspb.CryptoKey_ASYMMETRIC_SIGN,
			Algorithm:       kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256,
			ProtectionLevel: kmspb.ProtectionLevel_HSM,
		},
		{
			Name:            "SIGN_P384_SOFTWARE",
			Purpose:         kmspb.CryptoKey_ASYMMETRIC_SIGN,
			Algorithm:       kmspb.CryptoKeyVersion_EC_SIGN_P384_SHA384,
			ProtectionLevel: kmspb.ProtectionLevel_SOFTWARE,
		},
		{
			Name:            "SIGN_RSA3072PKCS1_SOFTWARE",
			Purpose:         kmspb.CryptoKey_ASYMMETRIC_SIGN,
			Algorithm:       kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_3072_SHA256,
			ProtectionLevel: kmspb.ProtectionLevel_SOFTWARE,
		},
		{
			Name:            "SIGN_RSAPSS4096SHA512_HSM",
			Purpose:         kmspb.CryptoKey_ASYMMETRIC_SIGN,
			Algorithm:       kmspb.CryptoKeyVersion_RSA_SIGN_PSS_4096_SHA512,
			ProtectionLevel: kmspb.ProtectionLevel_HSM,
		},
		{
			Name:            "ASYMM_DECRYPT_OAEP2048_SOFTWARE",
			Purpose:         kmspb.CryptoKey_ASYMMETRIC_DECRYPT,
			Algorithm:       kmspb.CryptoKeyVersion_RSA_DECRYPT_OAEP_2048_SHA256,
			ProtectionLevel: kmspb.ProtectionLevel_SOFTWARE,
		},
		{
			Name:            "ASYMM_DECRYPT_OAEP4096SHA256_HSM",
			Purpose:         kmspb.CryptoKey_ASYMMETRIC_DECRYPT,
			Algorithm:       kmspb.CryptoKeyVersion_RSA_DECRYPT_OAEP_4096_SHA256,
			ProtectionLevel: kmspb.ProtectionLevel_HSM,
		},
	}

	for _, c := range cases {
		t.Run(c.Name, func(t *testing.T) {
			keyID := testutil.RandomID(t)
			got, err := client.CreateCryptoKey(ctx, &kmspb.CreateCryptoKeyRequest{
				Parent:      kr.Name,
				CryptoKeyId: keyID,
				CryptoKey: &kmspb.CryptoKey{
					Purpose: c.Purpose,
					VersionTemplate: &kmspb.CryptoKeyVersionTemplate{
						ProtectionLevel: c.ProtectionLevel,
						Algorithm:       c.Algorithm,
					},
				},
				SkipInitialVersionCreation: true,
			})
			if err != nil {
				t.Fatal(err)
			}

			want := &kmspb.CryptoKey{
				Name:       fmt.Sprintf("%s/cryptoKeys/%s", kr.Name, keyID),
				CreateTime: ptypes.TimestampNow(),
				Purpose:    c.Purpose,
				VersionTemplate: &kmspb.CryptoKeyVersionTemplate{
					ProtectionLevel: c.ProtectionLevel,
					Algorithm:       c.Algorithm,
				},
			}

			if diff := cmp.Diff(want, got, testutil.ProtoDiffOpts()...); diff != "" {
				t.Errorf("unexpected diff (-want +got): %s", diff)
			}
		})
	}
}

func TestCreateCryptoKeyMalformedParent(t *testing.T) {
	ctx := context.Background()

	_, err := client.CreateCryptoKey(ctx, &kmspb.CreateCryptoKeyRequest{
		Parent:      "locations/foo",
		CryptoKeyId: "bar",
		CryptoKey: &kmspb.CryptoKey{
			Purpose: kmspb.CryptoKey_ENCRYPT_DECRYPT,
		},
		SkipInitialVersionCreation: true,
	})
	if status.Code(err) != codes.InvalidArgument {
		t.Errorf("err=%v, want code=InvalidArgument", err)
	}
}

func TestCreateCryptoKeyMalformedID(t *testing.T) {
	ctx := context.Background()

	kr, err := client.CreateKeyRing(ctx, &kmspb.CreateKeyRingRequest{
		Parent:    location,
		KeyRingId: testutil.RandomID(t),
	})
	if err != nil {
		t.Fatal(err)
	}

	_, err = client.CreateCryptoKey(ctx, &kmspb.CreateCryptoKeyRequest{
		Parent:      kr.Name,
		CryptoKeyId: "&bar",
		CryptoKey: &kmspb.CryptoKey{
			Purpose: kmspb.CryptoKey_ENCRYPT_DECRYPT,
		},
		SkipInitialVersionCreation: true,
	})
	if status.Code(err) != codes.InvalidArgument {
		t.Errorf("err=%v, want code=InvalidArgument", err)
	}
}

func TestCreateCryptoKeyDuplicateName(t *testing.T) {
	ctx := context.Background()

	kr, err := client.CreateKeyRing(ctx, &kmspb.CreateKeyRingRequest{
		Parent:    location,
		KeyRingId: testutil.RandomID(t),
	})
	if err != nil {
		t.Fatal(err)
	}

	req := &kmspb.CreateCryptoKeyRequest{
		Parent:      kr.Name,
		CryptoKeyId: "bar",
		CryptoKey: &kmspb.CryptoKey{
			Purpose: kmspb.CryptoKey_ENCRYPT_DECRYPT,
		},
		SkipInitialVersionCreation: true,
	}

	if _, err := client.CreateCryptoKey(ctx, req); err != nil {
		t.Fatal(err)
	}

	if _, err := client.CreateCryptoKey(ctx, req); status.Code(err) != codes.AlreadyExists {
		t.Errorf("err=%v, want code=AlreadyExists", err)
	}
}

func TestCreateCryptoKeyMissingAlgorithm(t *testing.T) {
	ctx := context.Background()

	kr, err := client.CreateKeyRing(ctx, &kmspb.CreateKeyRingRequest{
		Parent:    location,
		KeyRingId: testutil.RandomID(t),
	})
	if err != nil {
		t.Fatal(err)
	}

	// ASYMMETRIC_SIGN and ASYMMETRIC_DECRYPT must have algorithm supplied
	purposes := []kmspb.CryptoKey_CryptoKeyPurpose{
		kmspb.CryptoKey_ASYMMETRIC_DECRYPT, kmspb.CryptoKey_ASYMMETRIC_SIGN,
	}

	for _, p := range purposes {
		_, err = client.CreateCryptoKey(ctx, &kmspb.CreateCryptoKeyRequest{
			Parent:      kr.Name,
			CryptoKeyId: testutil.RandomID(t),
			CryptoKey: &kmspb.CryptoKey{
				Purpose: p,
			},
			SkipInitialVersionCreation: true,
		})
		if status.Code(err) != codes.InvalidArgument {
			t.Errorf("err=%v, want code=InvalidArgument", err)
		}
	}
}
