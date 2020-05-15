package fakekms

import (
	"context"
	"strings"
	"sync"

	"github.com/golang/protobuf/proto"
	"google.golang.org/grpc"
)

func newLockInterceptor(mux *sync.RWMutex) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		methodParts := strings.Split(info.FullMethod, "/")
		svc, method := methodParts[1], methodParts[2]

		if svc != "google.cloud.kms.v1.KeyManagementService" {
			return nil, errUnimplemented("unsupported service: %s", svc)
		}

		var locker sync.Locker
		switch method {
		case "GetCryptoKey", "GetCryptoKeyVersion", "GetKeyRing",
			"ListCryptoKeys", "ListCryptoKeyVersions", "ListKeyRings":
			locker = mux.RLocker()
		case "CreateCryptoKey", "CreateCryptoKeyVersion", "CreateKeyRing",
			"UpdateCryptoKey", "UpdateCryptoKeyVersion":
			locker = mux
		default:
			return nil, errUnimplemented("unsupported method: %s", info.FullMethod)
		}

		locker.Lock()
		defer locker.Unlock()

		resp, err := handler(ctx, req)
		if err != nil {
			return nil, err
		}

		// The response message (or one of its nested messages) might be shared.
		// Guarantee thread safety by cloning the response while we hold the lock.
		respMsg, ok := resp.(proto.Message)
		if !ok {
			return nil, errInternal("resp.(type)=%T, want proto.Message", resp)
		}
		return proto.Clone(respMsg), nil
	}
}
