package contract

import (
	"context"
	"testing"

	"oss-tools/kmsp11/test/fakekms/testutil"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	kmspb "google.golang.org/genproto/googleapis/cloud/kms/v1"
)

func TestListKeyRingsSorted(t *testing.T) {
	ctx := context.Background()

	// In real KMS, we can't depend on beginning state being empty. We're
	// creating two key rings here just to make sure that two (or more) exist--
	// they may not be the first two that are returned in the list request.
	if _, err := client.CreateKeyRing(ctx, &kmspb.CreateKeyRingRequest{
		Parent:    location,
		KeyRingId: testutil.RandomID(t),
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := client.CreateKeyRing(ctx, &kmspb.CreateKeyRingRequest{
		Parent:    location,
		KeyRingId: testutil.RandomID(t),
	}); err != nil {
		t.Fatal(err)
	}

	iter := client.ListKeyRings(ctx, &kmspb.ListKeyRingsRequest{Parent: location})

	r1, err := iter.Next()
	if err != nil {
		t.Fatalf("first call to iter.Next() resulted in error=%v, want nil", err)
	}

	r2, err := iter.Next()
	if err != nil {
		t.Fatalf("second call to iter.Next() resulted in error=%v, want nil", err)
	}

	if r1.Name > r2.Name {
		t.Errorf("r1.Name=%s > r2.Name=%s", r1.Name, r2.Name)
	}
}

func TestListKeyRingsMalformedParent(t *testing.T) {
	ctx := context.Background()

	iter := client.ListKeyRings(ctx, &kmspb.ListKeyRingsRequest{
		Parent: "locations/foo",
	})
	if _, err := iter.Next(); status.Code(err) != codes.InvalidArgument {
		t.Errorf("err=%v, want code=InvalidArgument", err)
	}
}
