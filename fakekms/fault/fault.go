package fault

import (
	"context"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/status"

	"cloud.google.com/kms/oss/fakekms/fault/faultpb"
	"google.golang.org/protobuf/types/known/emptypb"
)

var _ faultpb.FaultServiceServer = (*Server)(nil)

type Server struct {
	lock   sync.Mutex
	faults []*faultpb.Fault
}

func (s *Server) AddFault(ctx context.Context, fault *faultpb.Fault) (*emptypb.Empty, error) {
	s.lock.Lock()
	defer s.lock.Unlock()

	s.faults = append(s.faults, fault)
	return &emptypb.Empty{}, nil
}

// Returns an appropriate ResponseAction for the method, or nil if
// normal processing should be used.
func (s *Server) findFaultResponse(method string) *faultpb.ResponseAction {
	s.lock.Lock()
	defer s.lock.Unlock()

	matchIdx := -1
	var action *faultpb.ResponseAction
	for i, f := range s.faults {
		rm := f.GetRequestMatcher()
		if rm.GetMethodName() == "" || rm.GetMethodName() == method {
			action = f.ResponseAction
			matchIdx = i
			break
		}
	}

	if matchIdx >= 0 {
		// Consume the fault by removing it from the slice.
		s.faults = append(s.faults[:matchIdx], s.faults[matchIdx+1:]...)
	}
	return action
}

func (s *Server) NewInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		// Don't attempt to match on requests meant for the FaultService.
		if strings.HasPrefix(info.FullMethod, "/fakekms.FaultService/") {
			return handler(ctx, req)
		}

		// FullMethod looks like "/foo.package.BarService/BazMethod"
		method := strings.Split(info.FullMethod, "/")[2]
		action := s.findFaultResponse(method)
		if action.GetDelay() != nil {
			time.Sleep(action.Delay.AsDuration())
		}
		if action.GetError() != nil {
			return nil, status.ErrorProto(action.Error)
		}
		return handler(ctx, req)
	}
}
