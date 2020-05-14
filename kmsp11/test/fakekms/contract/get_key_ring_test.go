package contract

import (
	"context"
	"fmt"
	"testing"

	"oss-tools/kmsp11/test/fakekms/testutil"

	"github.com/google/go-cmp/cmp"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	kmspb "google.golang.org/genproto/googleapis/cloud/kms/v1"
)

func TestGetKeyRingEqualsCreated(t *testing.T) {
	ctx := context.Background()

	want, err := client.CreateKeyRing(ctx, &kmspb.CreateKeyRingRequest{
		Parent:    location,
		KeyRingId: testutil.RandomID(t),
	})
	if err != nil {
		t.Fatal(err)
	}

	got, err := client.GetKeyRing(ctx, &kmspb.GetKeyRingRequest{
		Name: want.Name,
	})
	if err != nil {
		t.Error(err)
	}

	if diff := cmp.Diff(want, got, testutil.ProtoDiffOpts()...); diff != "" {
		t.Errorf("proto mismatch (-want +got): %s", diff)
	}
}

func TestGetKeyRingMalformedName(t *testing.T) {
	ctx := context.Background()

	_, err := client.GetKeyRing(ctx, &kmspb.GetKeyRingRequest{
		Name: "malformed name",
	})
	if status.Code(err) != codes.InvalidArgument {
		t.Errorf("err=%v, want code=InvalidArgument", err)
	}
}

func TestGetKeyRingNotFound(t *testing.T) {
	ctx := context.Background()

	_, err := client.GetKeyRing(ctx, &kmspb.GetKeyRingRequest{
		Name: fmt.Sprintf("%s/keyRings/%s", location, testutil.RandomID(t)),
	})
	if status.Code(err) != codes.NotFound {
		t.Errorf("err=%v, want code=NotFound", err)
	}
}
