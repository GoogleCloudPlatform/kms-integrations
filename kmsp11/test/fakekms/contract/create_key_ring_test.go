package contract

import (
	"context"
	"fmt"
	"oss-tools/kmsp11/test/fakekms/testutil"
	"testing"

	"github.com/golang/protobuf/ptypes"
	"github.com/google/go-cmp/cmp"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	kmspb "google.golang.org/genproto/googleapis/cloud/kms/v1"
)

func TestCreateKeyRing(t *testing.T) {
	ctx := context.Background()
	keyRingID := testutil.RandomID(t)

	got, err := client.CreateKeyRing(ctx, &kmspb.CreateKeyRingRequest{
		Parent:    location,
		KeyRingId: keyRingID,
	})
	if err != nil {
		t.Fatal(err)
	}

	want := &kmspb.KeyRing{
		Name:       fmt.Sprintf("%s/keyRings/%s", location, keyRingID),
		CreateTime: ptypes.TimestampNow(),
	}

	if diff := cmp.Diff(want, got, testutil.ProtoDiffOpts()...); diff != "" {
		t.Errorf("unexpected diff (-want +got): %s", diff)
	}
}

func TestCreateKeyRingMalformedParent(t *testing.T) {
	ctx := context.Background()

	_, err := client.CreateKeyRing(ctx, &kmspb.CreateKeyRingRequest{
		Parent:    "locations/foo",
		KeyRingId: "bar",
	})
	if status.Code(err) != codes.InvalidArgument {
		t.Errorf("err=%v, want code=InvalidArgument", err)
	}
}

func TestCreateKeyRingMalformedID(t *testing.T) {
	ctx := context.Background()

	_, err := client.CreateKeyRing(ctx, &kmspb.CreateKeyRingRequest{
		Parent:    location,
		KeyRingId: "&bar",
	})
	if status.Code(err) != codes.InvalidArgument {
		t.Errorf("err=%v, want code=InvalidArgument", err)
	}
}

func TestCreateKeyRingDuplicateName(t *testing.T) {
	ctx := context.Background()

	req := &kmspb.CreateKeyRingRequest{
		Parent:    location,
		KeyRingId: testutil.RandomID(t),
	}

	if _, err := client.CreateKeyRing(ctx, req); err != nil {
		t.Fatal(err)
	}

	if _, err := client.CreateKeyRing(ctx, req); status.Code(err) != codes.AlreadyExists {
		t.Errorf("err=%v, want code=AlreadyExists", err)
	}
}
