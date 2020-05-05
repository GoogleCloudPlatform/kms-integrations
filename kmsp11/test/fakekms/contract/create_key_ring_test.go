package contract

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/golang/protobuf/ptypes"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	kmspb "google.golang.org/genproto/googleapis/cloud/kms/v1"
)

func TestCreatedKeyRingNamePattern(t *testing.T) {
	ctx := context.Background()
	keyRingID := randomID(t)

	kr, err := client.CreateKeyRing(ctx, &kmspb.CreateKeyRingRequest{
		Parent:    location,
		KeyRingId: keyRingID,
	})
	if err != nil {
		t.Fatal(err)
	}

	want := fmt.Sprintf("%s/keyRings/%s", location, keyRingID)
	if kr.Name != want {
		t.Errorf("kr.Name=%s, want %s", kr.Name, want)
	}
}

func TestCreatedKeyRingCreateTimestamp(t *testing.T) {
	ctx := context.Background()

	kr, err := client.CreateKeyRing(ctx, &kmspb.CreateKeyRingRequest{
		Parent:    location,
		KeyRingId: randomID(t),
	})
	if err != nil {
		t.Fatal(err)
	}
	ts, err := ptypes.Timestamp(kr.CreateTime)
	if err != nil {
		t.Fatal(err)
	}

	// allow for up to two minutes of clock skew
	min := time.Now().Add(-2 * time.Minute)
	max := min.Add(4 * time.Minute)
	if min.After(ts) || max.Before(ts) {
		t.Errorf("kr.CreateTimestamp=%s, want between %s and %s", ts, min, max)
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
		KeyRingId: randomID(t),
	}

	if _, err := client.CreateKeyRing(ctx, req); err != nil {
		t.Fatal(err)
	}

	if _, err := client.CreateKeyRing(ctx, req); status.Code(err) != codes.AlreadyExists {
		t.Errorf("err=%v, want code=AlreadyExists", err)
	}
}
