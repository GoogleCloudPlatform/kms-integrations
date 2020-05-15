package fakekms

import (
	"fmt"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func errAlreadyExists(name fmt.Stringer) error {
	return status.Errorf(codes.AlreadyExists, "already exists: %s", name)
}

func errFailedPrecondition(format string, a ...interface{}) error {
	return status.Errorf(codes.FailedPrecondition, format, a...)
}

func errInternal(format string, a ...interface{}) error {
	return status.Errorf(codes.Internal, format, a...)
}

func errInvalidArgument(format string, a ...interface{}) error {
	return status.Errorf(codes.InvalidArgument, format, a...)
}

func errMalformedName(resourceType, invalidName string) error {
	return status.Errorf(codes.InvalidArgument, "invalid %s name: %s", resourceType, invalidName)
}

func errMaxPageSize(resultCount int) error {
	return errUnimplemented("no pagination in fakekms: result count %d exceeds max page size (%d)",
		resultCount, maxPageSize)
}

func errNotFound(name fmt.Stringer) error {
	return status.Errorf(codes.NotFound, "not found: %s", name)
}

func errRequiredField(fieldName string) error {
	return status.Errorf(codes.InvalidArgument, "field %q is required", fieldName)
}

func errUnimplemented(format string, a ...interface{}) error {
	return status.Errorf(codes.Unimplemented, format, a...)
}
