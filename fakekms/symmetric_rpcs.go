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
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"io"

	kmspb "google.golang.org/genproto/googleapis/cloud/kms/v1"
)

// maxPlaintextSize is the maximum plaintext size accepted by Cloud KMS.
const maxPlaintextSize = 64 * 1024

// maxCiphertextSize is the maximum ciphertext size accepted by Cloud KMS.
const maxCiphertextSize = 10 * maxPlaintextSize

// RawEncrypt fakes a Cloud KMS API function.
func (f *fakeKMS) RawEncrypt(ctx context.Context, req *kmspb.RawEncryptRequest) (*kmspb.RawEncryptResponse, error) {
	if err := allowlist("name", "plaintext", "additional_authenticated_data").check(req); err != nil {
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
	if def.Purpose != kmspb.CryptoKey_RAW_ENCRYPT_DECRYPT {
		return nil, errFailedPrecondition("keys with algorithm %s may not be used for raw encryption",
			nameForValue(kmspb.CryptoKeyVersion_CryptoKeyVersionAlgorithm_name, int32(ckv.pb.Algorithm)))
	}

	if req.Plaintext == nil {
		return nil, errInvalidArgument("plaintext is empty")
	}
	var plaintext []byte = req.Plaintext

	if len(plaintext) > maxPlaintextSize {
		return nil, errInvalidArgument("len(plaintext)=%d, want len(plaintext)<=%d", len(plaintext), maxPlaintextSize)
	}

	var key []byte
	var ok bool
	if key, ok = ckv.keyMaterial.([]byte); !ok {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, errInternal("AES cipher creation failed: %v", err)
	}

	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, errInternal("GCM cipher creation failed: %v", err)
	}

	ciphertext := aesgcm.Seal(nil, nonce, plaintext, req.AdditionalAuthenticatedData)

	return &kmspb.RawEncryptResponse{
		Name:                       req.Name,
		Ciphertext:                 ciphertext,
		CiphertextCrc32C:           crc32c(ciphertext),
		InitializationVector:       nonce,
		InitializationVectorCrc32C: crc32c(nonce),
		TagLength:                  16,
		ProtectionLevel:            ckv.pb.ProtectionLevel,
	}, nil
}

// RawDecrypt fakes a Cloud KMS API function.
func (f *fakeKMS) RawDecrypt(ctx context.Context, req *kmspb.RawDecryptRequest) (*kmspb.RawDecryptResponse, error) {
	if err := allowlist("name", "ciphertext", "additional_authenticated_data", "initialization_vector").check(req); err != nil {
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
	if def.Purpose != kmspb.CryptoKey_RAW_ENCRYPT_DECRYPT {
		return nil, errFailedPrecondition("keys with algorithm %s may not be used for raw decryption",
			nameForValue(kmspb.CryptoKeyVersion_CryptoKeyVersionAlgorithm_name, int32(ckv.pb.Algorithm)))
	}

	if req.Ciphertext == nil {
		return nil, errInvalidArgument("ciphertext is empty")
	}
	var ciphertext []byte = req.Ciphertext

	if len(ciphertext) > maxCiphertextSize {
		return nil, errInvalidArgument("len(ciphertext)=%d, want len(ciphertext)<=%d", len(ciphertext), maxCiphertextSize)
	}

	if len(req.InitializationVector) != 12 {
		return nil, errInvalidArgument("len(initialization_vector)=%d, want 12", len(req.InitializationVector))
	}

	var key []byte
	var ok bool
	if key, ok = ckv.keyMaterial.([]byte); !ok {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, errInternal("AES cipher creation failed: %v", err)
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, errInternal("GCM cipher creation failed: %v", err)
	}

	plaintext, err := aesgcm.Open(nil, req.InitializationVector, ciphertext, req.AdditionalAuthenticatedData)
	if err != nil {
		return nil, errInternal("decryption failed: %v", err)
	}

	return &kmspb.RawDecryptResponse{
		Plaintext:       plaintext,
		PlaintextCrc32C: crc32c(plaintext),
		ProtectionLevel: ckv.pb.ProtectionLevel,
	}, nil
}

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
