package contract

import (
	"context"
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	kmspb "google.golang.org/genproto/googleapis/cloud/kms/v1"
)

func TestGetKeyRingEqualsCreated(t *testing.T) {
	ctx := context.Background()
	want := client.CreateTestKR(ctx, t, &kmspb.CreateKeyRingRequest{Parent: location})

	got, err := client.GetKeyRing(ctx, &kmspb.GetKeyRingRequest{
		Name: want.Name,
	})
	if err != nil {
		t.Error(err)
	}

	if diff := cmp.Diff(want, got, ProtoDiffOpts()...); diff != "" {
		t.Errorf("proto mismatch (-want +got): %s", diff)
	}
}

func TestGetKeyRingMalformedName(t *testing.T) {
	ctx := context.Background()

	_, err := client.GetKeyRing(ctx, &kmspb.GetKeyRingRequest{
		Name: "malformed name",
	})
	if status.Code(err) != codes.InvalidArgument {
		t.Errorf("err=%v, want code=%s", err, codes.InvalidArgument)
	}
}

func TestGetKeyRingNotFound(t *testing.T) {
	ctx := context.Background()

	_, err := client.GetKeyRing(ctx, &kmspb.GetKeyRingRequest{
		Name: fmt.Sprintf("%s/keyRings/%s", location, RandomID(t)),
	})
	if status.Code(err) != codes.NotFound {
		t.Errorf("err=%v, want code=%s", err, codes.NotFound)
	}
}
