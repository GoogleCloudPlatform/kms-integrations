package fakekms

import (
	"fmt"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func errAlreadyExists(name fmt.Stringer) error {
	return status.Errorf(codes.AlreadyExists, "already exists: %s", name)
}

func errInvalidArgument(format string, a ...interface{}) error {
	return status.Errorf(codes.InvalidArgument, format, a...)
}

func errMalformedName(resourceType, invalidName string) error {
	return status.Errorf(codes.InvalidArgument, "invalid %s name: %s", resourceType, invalidName)
}

func errNotFound(name fmt.Stringer) error {
	return status.Errorf(codes.NotFound, "not found: %s", name)
}
