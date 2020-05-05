package fakekms

import (
	"context"

	"github.com/golang/protobuf/ptypes"

	kmspb "google.golang.org/genproto/googleapis/cloud/kms/v1"
)

// CreateKeyRing fakes a Cloud KMS API function.
func (f *fakeKMS) CreateKeyRing(ctx context.Context, req *kmspb.CreateKeyRingRequest) (*kmspb.KeyRing, error) {
	// TODO(bdhess): revisit handling of output-only fields (http://g/api-discuss/vUowIGKPFT4)
	if err := whitelist("parent", "key_ring_id").check(req); err != nil {
		return nil, err
	}

	parent, err := parseLocationName(req.Parent)
	if err != nil {
		return nil, err
	}
	if err := checkID(req.KeyRingId); err != nil {
		return nil, err
	}

	name := keyRingName{locationName: parent, KeyRingID: req.KeyRingId}
	if _, ok := f.keyRings[name]; ok {
		return nil, errAlreadyExists(name)
	}

	pb := &kmspb.KeyRing{
		Name:       name.String(),
		CreateTime: ptypes.TimestampNow(),
	}
	f.keyRings[name] = &keyRing{pb: pb}
	return pb, nil
}

// GetKeyRing fakes a Cloud KMS API function.
func (f *fakeKMS) GetKeyRing(ctx context.Context, req *kmspb.GetKeyRingRequest) (*kmspb.KeyRing, error) {
	if err := whitelist("name").check(req); err != nil {
		return nil, err
	}

	name, err := parseKeyRingName(req.Name)
	if err != nil {
		return nil, err
	}

	kr, ok := f.keyRings[name]
	if !ok {
		return nil, errNotFound(name)
	}
	return kr.pb, nil
}
