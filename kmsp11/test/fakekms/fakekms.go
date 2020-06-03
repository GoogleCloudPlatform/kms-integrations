// Package fakekms contains a fake of the Google Cloud Key Management service.
// go/mocks#prefer-fakes
package fakekms

import (
	"net"
	"sync"

	"google.golang.org/grpc"

	kmspb "google.golang.org/genproto/googleapis/cloud/kms/v1"
)

// maxPageSize is the maximum number of elements that will be returned in
// a single paged result of a list request.
const maxPageSize = 1000

// fakeKMS implements a fake of the Cloud KMS API.
type fakeKMS struct {
	kmspb.UnimplementedKeyManagementServiceServer
	keyRings map[keyRingName]*keyRing

	// Protects keyRings. For guarding object use within RPCs, the lock is held
	// in the lock interceptor rather than directly in the RPC function.
	mux sync.RWMutex
}

// keyRing models a KeyRing in Cloud KMS.
type keyRing struct {
	pb   *kmspb.KeyRing
	keys map[cryptoKeyName]*cryptoKey
}

// cryptoKey models a CryptoKey in Cloud KMS.
type cryptoKey struct {
	pb       *kmspb.CryptoKey
	versions map[cryptoKeyVersionName]*cryptoKeyVersion
}

func (f *fakeKMS) cryptoKey(name cryptoKeyName) (*cryptoKey, error) {
	kr, ok := f.keyRings[name.keyRingName]
	if !ok {
		return nil, errNotFound(name)
	}
	ck, ok := kr.keys[name]
	if !ok {
		return nil, errNotFound(name)
	}
	return ck, nil
}

// cryptoKeyVersion models a CryptoKeyVersion in Cloud KMS.
type cryptoKeyVersion struct {
	pb          *kmspb.CryptoKeyVersion
	keyMaterial interface{}
}

func (f *fakeKMS) cryptoKeyVersion(name cryptoKeyVersionName) (*cryptoKeyVersion, error) {
	kr, ok := f.keyRings[name.keyRingName]
	if !ok {
		return nil, errNotFound(name)
	}
	ck, ok := kr.keys[name.cryptoKeyName]
	if !ok {
		return nil, errNotFound(name)
	}
	ckv, ok := ck.versions[name]
	if !ok {
		return nil, errNotFound(name)
	}
	return ckv, nil
}

// Server wraps a local gRPC server that serves KMS requests.
type Server struct {
	Addr       net.Addr
	grpcServer *grpc.Server
}

// Close stops the server by immediately closing all connections and listeners.
func (s *Server) Close() {
	s.grpcServer.Stop()
}

// NewServer starts a new local Fake KMS server that is listening for gRPC requests.
func NewServer() (*Server, error) {
	lis, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		return nil, err
	}

	f := &fakeKMS{keyRings: make(map[keyRingName]*keyRing)}
	s := grpc.NewServer(grpc.ChainUnaryInterceptor(newLockInterceptor(&f.mux)))
	kmspb.RegisterKeyManagementServiceServer(s, f)

	go s.Serve(lis)
	return &Server{Addr: lis.Addr(), grpcServer: s}, nil
}
