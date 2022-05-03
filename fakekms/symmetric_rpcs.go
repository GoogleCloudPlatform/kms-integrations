// Copyright 2022 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package fakekms

import (
	"context"
	"crypto"
	"crypto/hmac"

	kmspb "google.golang.org/genproto/googleapis/cloud/kms/v1"
)

// MacSign fakes a Cloud KMS API function.
func (f *fakeKMS) MacSign(ctx context.Context, req *kmspb.MacSignRequest) (*kmspb.MacSignResponse, error) {
	if err := allowlist("name", "data").check(req); err != nil {
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

	if ckv.pb.State != kmspb.CryptoKeyVersion_ENABLED {
		return nil, errFailedPrecondition("key version %s is not enabled", name)
	}

	def, _ := algorithmDef(ckv.pb.Algorithm)
	if def.Purpose != kmspb.CryptoKey_MAC {
		return nil, errFailedPrecondition("keys with algorithm %s may not be used for MAC signing",
			nameForValue(kmspb.CryptoKeyVersion_CryptoKeyVersionAlgorithm_name, int32(ckv.pb.Algorithm)))
	}

	hash := def.Opts.(crypto.Hash)

	if req.Data == nil {
		return nil, errInvalidArgument("data is empty")
	}
	var data []byte = req.Data

	if len(data) > 64*1024 {
		return nil, errInvalidArgument("len(data)=%d, want len(data)<=%d", len(data), 64*1024)
	}

	var key []byte
	var ok bool
	if key, ok = ckv.keyMaterial.([]byte); !ok {
		return nil, err
	}

	mac := hmac.New(hash.New, key)
	_, err = mac.Write(data)
	if err != nil {
		return nil, errInternal("MAC signing failed: %v", err)
	}
	macTag := mac.Sum(nil)

	return &kmspb.MacSignResponse{
		Name:            req.Name,
		Mac:             macTag,
		MacCrc32C:       crc32c(macTag),
		ProtectionLevel: ckv.pb.ProtectionLevel,
	}, nil
}

// MacVerify fakes a Cloud KMS API function.
func (f *fakeKMS) MacVerify(ctx context.Context, req *kmspb.MacVerifyRequest) (*kmspb.MacVerifyResponse, error) {
	if err := allowlist("name", "data", "mac").check(req); err != nil {
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

	if ckv.pb.State != kmspb.CryptoKeyVersion_ENABLED {
		return nil, errFailedPrecondition("key version %s is not enabled", name)
	}

	def, _ := algorithmDef(ckv.pb.Algorithm)
	if def.Purpose != kmspb.CryptoKey_MAC {
		return nil, errFailedPrecondition("keys with algorithm %s may not be used for MAC verification",
			nameForValue(kmspb.CryptoKeyVersion_CryptoKeyVersionAlgorithm_name, int32(ckv.pb.Algorithm)))
	}

	if req.Data == nil {
		return nil, errInvalidArgument("data is empty")
	}
	var data []byte = req.Data

	if len(data) > 64*1024 {
		return nil, errInvalidArgument("len(data)=%d, want len(data)<=%d", len(data), 64*1024)
	}

	hash := def.Opts.(crypto.Hash)

	if req.Mac == nil {
		return nil, errInvalidArgument("mac is empty")
	}

	if len(req.Mac) != hash.Size() {
		return nil, errInvalidArgument("len(mac)=%d, want %d", len(req.Mac), hash.Size())
	}

	var key []byte
	var ok bool
	if key, ok = ckv.keyMaterial.([]byte); !ok {
		return nil, err
	}

	mac := hmac.New(hash.New, key)
	_, err = mac.Write(data)
	if err != nil {
		return nil, errInternal("MAC signing failed: %v", err)
	}
	macTag := mac.Sum(nil)

	return &kmspb.MacVerifyResponse{
		Name:                     req.Name,
		Success:                  hmac.Equal(req.Mac, macTag),
		VerifiedSuccessIntegrity: hmac.Equal(req.Mac, macTag),
		ProtectionLevel:          ckv.pb.ProtectionLevel,
	}, nil
}
