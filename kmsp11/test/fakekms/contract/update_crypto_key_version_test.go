package contract

import (
	"context"
	"testing"

	"oss-tools/kmsp11/test/fakekms/testutil"

	"github.com/google/go-cmp/cmp"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	kmspb "google.golang.org/genproto/googleapis/cloud/kms/v1"
	fmpb "google.golang.org/genproto/protobuf/field_mask"
)

func TestUpdateCryptoKeyVersionDisableEnable(t *testing.T) {
	ctx := context.Background()

	kr, err := client.CreateKeyRing(ctx, &kmspb.CreateKeyRingRequest{
		Parent:    location,
		KeyRingId: testutil.RandomID(t),
	})
	if err != nil {
		t.Fatal(err)
	}

	ck, err := client.CreateCryptoKey(ctx, &kmspb.CreateCryptoKeyRequest{
		Parent:      kr.Name,
		CryptoKeyId: "foo",
		CryptoKey: &kmspb.CryptoKey{
			Purpose: kmspb.CryptoKey_ENCRYPT_DECRYPT,
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	// ensure that enabled => disabled is permitted
	ck.Primary.State = kmspb.CryptoKeyVersion_DISABLED
	gotVersion, err := client.UpdateCryptoKeyVersion(ctx, &kmspb.UpdateCryptoKeyVersionRequest{
		CryptoKeyVersion: ck.Primary,
		UpdateMask: &fmpb.FieldMask{
			Paths: []string{"state"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if diff := cmp.Diff(ck.Primary, gotVersion, testutil.ProtoDiffOpts()...); diff != "" {
		t.Errorf("ckv proto mismatch on disable RPC (-want +got): %s", diff)
	}

	// ensure that `primary` in GetCryptoKey is updated too
	gotKey, err := client.GetCryptoKey(ctx, &kmspb.GetCryptoKeyRequest{Name: ck.Name})
	if err != nil {
		t.Fatal(err)
	}
	if diff := cmp.Diff(ck, gotKey, testutil.ProtoDiffOpts()...); diff != "" {
		t.Errorf("ck proto mismatch after disable RPC (-want +got): %s", diff)
	}

	// ensure that disabled => enabled is permitted
	ck.Primary.State = kmspb.CryptoKeyVersion_ENABLED
	gotVersion, err = client.UpdateCryptoKeyVersion(ctx, &kmspb.UpdateCryptoKeyVersionRequest{
		CryptoKeyVersion: ck.Primary,
		UpdateMask: &fmpb.FieldMask{
			Paths: []string{"state"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if diff := cmp.Diff(ck.Primary, gotVersion, testutil.ProtoDiffOpts()...); diff != "" {
		t.Errorf("ckv proto mismatch on enable RPC (-want +got): %s", diff)
	}
}

func TestUpdateCryptoKeyVersionNoFields(t *testing.T) {
	ctx := context.Background()

	kr, err := client.CreateKeyRing(ctx, &kmspb.CreateKeyRingRequest{
		Parent:    location,
		KeyRingId: testutil.RandomID(t),
	})
	if err != nil {
		t.Fatal(err)
	}

	ck, err := client.CreateCryptoKey(ctx, &kmspb.CreateCryptoKeyRequest{
		Parent:      kr.Name,
		CryptoKeyId: "foo",
		CryptoKey: &kmspb.CryptoKey{
			Purpose: kmspb.CryptoKey_ENCRYPT_DECRYPT,
		},
		SkipInitialVersionCreation: true,
	})
	if err != nil {
		t.Fatal(err)
	}

	ckv, err := client.CreateCryptoKeyVersion(ctx, &kmspb.CreateCryptoKeyVersionRequest{
		Parent: ck.Name,
	})
	if err != nil {
		t.Fatal(err)
	}

	_, err = client.UpdateCryptoKeyVersion(ctx, &kmspb.UpdateCryptoKeyVersionRequest{
		CryptoKeyVersion: ckv,
	})
	if status.Code(err) != codes.InvalidArgument {
		t.Errorf("err=%v, want code=%s", err, codes.InvalidArgument)
	}
}

func TestUpdateCryptoKeyVersionUnsupportedState(t *testing.T) {
	ctx := context.Background()

	kr, err := client.CreateKeyRing(ctx, &kmspb.CreateKeyRingRequest{
		Parent:    location,
		KeyRingId: testutil.RandomID(t),
	})
	if err != nil {
		t.Fatal(err)
	}

	ck, err := client.CreateCryptoKey(ctx, &kmspb.CreateCryptoKeyRequest{
		Parent:      kr.Name,
		CryptoKeyId: "foo",
		CryptoKey: &kmspb.CryptoKey{
			Purpose: kmspb.CryptoKey_ENCRYPT_DECRYPT,
		},
		SkipInitialVersionCreation: true,
	})
	if err != nil {
		t.Fatal(err)
	}

	ckv, err := client.CreateCryptoKeyVersion(ctx, &kmspb.CreateCryptoKeyVersionRequest{
		Parent: ck.Name,
	})
	if err != nil {
		t.Fatal(err)
	}

	ckv.State = kmspb.CryptoKeyVersion_PENDING_IMPORT

	_, err = client.UpdateCryptoKeyVersion(ctx, &kmspb.UpdateCryptoKeyVersionRequest{
		CryptoKeyVersion: ckv,
		UpdateMask: &fmpb.FieldMask{
			Paths: []string{"state"},
		},
	})
	if status.Code(err) != codes.InvalidArgument {
		t.Errorf("err=%v, want code=%s", err, codes.InvalidArgument)
	}
}

func TestUpdateCryptoKeyVersionUnsupportedField(t *testing.T) {
	ctx := context.Background()

	kr, err := client.CreateKeyRing(ctx, &kmspb.CreateKeyRingRequest{
		Parent:    location,
		KeyRingId: testutil.RandomID(t),
	})
	if err != nil {
		t.Fatal(err)
	}

	ck, err := client.CreateCryptoKey(ctx, &kmspb.CreateCryptoKeyRequest{
		Parent:      kr.Name,
		CryptoKeyId: "foo",
		CryptoKey: &kmspb.CryptoKey{
			Purpose: kmspb.CryptoKey_ENCRYPT_DECRYPT,
		},
		SkipInitialVersionCreation: true,
	})
	if err != nil {
		t.Fatal(err)
	}

	ckv, err := client.CreateCryptoKeyVersion(ctx, &kmspb.CreateCryptoKeyVersionRequest{
		Parent: ck.Name,
	})
	if err != nil {
		t.Fatal(err)
	}

	ckv.Name = "updated"

	_, err = client.UpdateCryptoKeyVersion(ctx, &kmspb.UpdateCryptoKeyVersionRequest{
		CryptoKeyVersion: ckv,
		UpdateMask: &fmpb.FieldMask{
			Paths: []string{"name"},
		},
	})
	if status.Code(err) != codes.InvalidArgument {
		t.Errorf("err=%v, want code=%s", err, codes.InvalidArgument)
	}
}
