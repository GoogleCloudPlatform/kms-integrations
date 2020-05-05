package contract

import (
	"context"
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/testing/protocmp"

	kmspb "google.golang.org/genproto/googleapis/cloud/kms/v1"
)

func TestGetKeyRingEqualsCreated(t *testing.T) {
	ctx := context.Background()

	want, err := client.CreateKeyRing(ctx, &kmspb.CreateKeyRingRequest{
		Parent:    location,
		KeyRingId: randomID(t),
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

	if diff := cmp.Diff(want, got, protocmp.Transform()); diff != "" {
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
		Name: fmt.Sprintf("%s/keyRings/%s", location, randomID(t)),
	})
	if status.Code(err) != codes.NotFound {
		t.Errorf("err=%v, want code=NotFound", err)
	}
}
