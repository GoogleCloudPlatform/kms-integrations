package contract

import (
	"testing"
	"time"

	"github.com/golang/protobuf/ptypes"
	"github.com/google/go-cmp/cmp"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"

	timestamppb "github.com/golang/protobuf/ptypes/timestamp"
)

// ProtoDiffOpts returns cmp.Options suitable for diffing KMS proto messages.
func ProtoDiffOpts() []cmp.Option {
	return []cmp.Option{protocmp.Transform(), EquateApproxTimestamp(time.Minute)}
}

// RandomID returns a string suitable for use as a KMS resource identifier.
func RandomID(t *testing.T) string {
	t.Helper()
	id, err := uuid.NewRandom()
	if err != nil {
		t.Fatal(err)
	}
	return id.String()
}

// EquateApproxTimestamp returns a Comparer option that determines two non-zero
// proto timestamp values to be equal if they are within some margin of one
// another.
//
// See also cmpopts.EquateApproxTime:
// https://pkg.go.dev/github.com/google/go-cmp/cmp/cmpopts?tab=doc#EquateApproxTime
func EquateApproxTimestamp(margin time.Duration) cmp.Option {
	if margin < 0 {
		panic("margin must be a non-negative number")
	}
	return protocmp.FilterMessage(&timestamppb.Timestamp{}, cmp.Comparer(func(x, y protocmp.Message) bool {
		diff, ok := timestampDiff(x, y)
		if !ok {
			// fall back to cmp.Equal if one of the messages is invalid or zero
			return cmp.Equal(x, y)
		}
		return diff <= margin
	}))
}

func comparableTime(msg proto.Message) (time.Time, bool) {
	ts := new(timestamppb.Timestamp)
	proto.Merge(ts, msg)
	t, err := ptypes.Timestamp(ts)
	return t, err == nil
}

// Returns the difference in times between the two timestamp messages as
// a time.Duration, or not OK if one of the messages is invalid or zero.
func timestampDiff(mx, my proto.Message) (diff time.Duration, ok bool) {
	if x, ok := comparableTime(mx); ok {
		if y, ok := comparableTime(my); ok {
			if !(x.IsZero() || y.IsZero()) {
				// ensure x <= y
				if x.After(y) {
					x, y = y, x
				}
				return y.Sub(x), true
			}
		}
	}
	return 0, false
}
