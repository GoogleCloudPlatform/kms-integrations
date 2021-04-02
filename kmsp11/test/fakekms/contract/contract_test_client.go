package contract

import (
	"context"
	"testing"
	"time"

	kms "cloud.google.com/go/kms/apiv1"
	"google.golang.org/protobuf/proto"

	kmspb "google.golang.org/genproto/googleapis/cloud/kms/v1"
)

// ContractTestClient is a key management client with additional helpers.
type ContractTestClient struct {
	*kms.KeyManagementClient
}

// CreateTestKR creates a KeyRing using the provided request.
func (c *ContractTestClient) CreateTestKR(ctx context.Context, t *testing.T, req *kmspb.CreateKeyRingRequest) *kmspb.KeyRing {
	t.Helper()

	r := &kmspb.CreateKeyRingRequest{
		KeyRingId: RandomID(t),
	}
	proto.Merge(r, req)

	kr, err := c.CreateKeyRing(ctx, r)
	if err != nil {
		t.Fatal(err)
	}

	return kr
}

// CreateTestCK creates a CryptoKey using the provided request.
func (c *ContractTestClient) CreateTestCK(ctx context.Context, t *testing.T, req *kmspb.CreateCryptoKeyRequest) *kmspb.CryptoKey {
	t.Helper()

	r := &kmspb.CreateCryptoKeyRequest{
		CryptoKeyId: RandomID(t),
	}
	proto.Merge(r, req)

	ck, err := c.CreateCryptoKey(ctx, r)
	if err != nil {
		t.Fatal(err)
	}

	return ck
}

// CreateTestCKVAndWait creates a CryptoKeyVersion with the provided request
// and waits for its state to be enabled before returning.
func (c *ContractTestClient) CreateTestCKVAndWait(ctx context.Context, t *testing.T, req *kmspb.CreateCryptoKeyVersionRequest) *kmspb.CryptoKeyVersion {
	t.Helper()

	ckv, err := c.CreateCryptoKeyVersion(ctx, req)
	if err != nil {
		t.Fatal(err)
	}

	for ckv.State == kmspb.CryptoKeyVersion_PENDING_GENERATION {
		time.Sleep(asyncPollInterval)
		ckv, err = c.GetCryptoKeyVersion(ctx, &kmspb.GetCryptoKeyVersionRequest{
			Name: ckv.Name,
		})
		if err != nil {
			t.Fatal(err)
		}
	}

	return ckv
}
