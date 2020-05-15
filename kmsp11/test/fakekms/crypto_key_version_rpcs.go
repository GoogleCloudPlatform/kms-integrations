package fakekms

import (
	"context"
	"strconv"

	"github.com/golang/protobuf/ptypes"

	kmspb "google.golang.org/genproto/googleapis/cloud/kms/v1"
)

// CreateCryptoKeyVersionVersion fakes a Cloud KMS API function.
func (f *fakeKMS) CreateCryptoKeyVersion(ctx context.Context, req *kmspb.CreateCryptoKeyVersionRequest) (*kmspb.CryptoKeyVersion, error) {
	if err := whitelist("parent").check(req); err != nil {
		return nil, err
	}

	ckName, err := parseCryptoKeyName(req.Parent)
	if err != nil {
		return nil, err
	}

	ck, err := f.cryptoKey(ckName)
	if err != nil {
		return nil, err
	}

	name := cryptoKeyVersionName{
		cryptoKeyName:      ckName,
		CryptoKeyVersionID: strconv.Itoa(len(ck.versions) + 1),
	}

	pb := &kmspb.CryptoKeyVersion{
		Name:            name.String(),
		CreateTime:      ptypes.TimestampNow(),
		Algorithm:       ck.pb.VersionTemplate.Algorithm,
		ProtectionLevel: ck.pb.VersionTemplate.ProtectionLevel,
	}

	switch ck.pb.Purpose {
	case kmspb.CryptoKey_ASYMMETRIC_DECRYPT, kmspb.CryptoKey_ASYMMETRIC_SIGN:
		// async generation
		pb.State = kmspb.CryptoKeyVersion_PENDING_GENERATION
		go func() {
			// Our lock interceptor ensures that f.mux is held whenever an RPC is in
			// flight. This goroutine won't be able to acquire f.mux until after the
			// CreateCryptoKeyVersion RPC completes. Since all RPCs acquire f.mux, we
			// can further guarantee that no other RPCs are in flight when this
			// routine proceeds.
			f.mux.Lock()
			defer f.mux.Unlock()

			pb.State = kmspb.CryptoKeyVersion_ENABLED
			pb.GenerateTime = ptypes.TimestampNow()
		}()

	default:
		// sync generation
		pb.State = kmspb.CryptoKeyVersion_ENABLED
		pb.GenerateTime = pb.CreateTime
	}

	ck.versions[name] = &cryptoKeyVersion{pb: pb}
	return pb, nil
}

// GetCryptoKeyVersion fakes a Cloud KMS API function.
func (f *fakeKMS) GetCryptoKeyVersion(ctx context.Context, req *kmspb.GetCryptoKeyVersionRequest) (*kmspb.CryptoKeyVersion, error) {
	if err := whitelist("name").check(req); err != nil {
		return nil, err
	}

	name, err := parseCryptoKeyVersionName(req.Name)
	if err != nil {
		return nil, err
	}

	ckv, err := f.cryptoKeyVersion(name)
	if err != nil {
		return nil, err
	}

	return ckv.pb, nil
}
