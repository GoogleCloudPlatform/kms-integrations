package contract

import (
	"math"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	timestamppb "github.com/golang/protobuf/ptypes/timestamp"
)

func ts(seconds int64, nanos int32) *timestamppb.Timestamp {
	return &timestamppb.Timestamp{Seconds: seconds, Nanos: nanos}
}

func TestTimestampDiffOK(t *testing.T) {
	var cases = []struct {
		Name string
		X, Y *timestamppb.Timestamp
		Want time.Duration
	}{
		{"NilEqualsNil", nil, nil, time.Duration(0)},
		{"NilEqualsZero", nil, ts(0, 0), time.Duration(0)},
		{"ZeroEqualsZero", ts(0, 0), ts(0, 0), time.Duration(0)},
		{"1ns", ts(0, 1), ts(0, 2), time.Nanosecond},
		{"2ns", ts(3, 3), ts(3, 1), 2 * time.Nanosecond},
		{"3ns", ts(0, 2), ts(0, 5), 3 * time.Nanosecond},
		{"1s", ts(2, 0), ts(1, 0), time.Second},
		{"2s", ts(12, 0), ts(14, 0), 2 * time.Second},
		{"1s1ns", ts(2, 1), ts(1, 0), time.Second + time.Nanosecond},
		{"2sMinus2ns", ts(3, 0), ts(1, 2), (2 * time.Second) - (2 * time.Nanosecond)},
	}

	for _, c := range cases {
		t.Run(c.Name, func(t *testing.T) {
			got, ok := timestampDiff(c.X, c.Y)
			if !ok {
				t.Fatal("got !ok")
			}
			if diff := cmp.Diff(c.Want, got); diff != "" {
				t.Errorf("timestamp mismatch (-want, +got): %s", diff)
			}
		})
	}
}

func TestTimestampDiffNotOK(t *testing.T) {
	var cases = []struct {
		Name string
		X, Y *timestamppb.Timestamp
	}{
		{"NanosTooSmall", ts(0, 0), ts(0, -int32(time.Second))},
		{"NanosTooLarge", ts(0, 0), ts(0, int32(time.Second))},
		{"SecondsTooSmall", ts(math.MinInt64, 0), ts(0, 1)},
		{"SecondsTooLarge", ts(math.MaxInt64, 0), ts(0, 1)},
	}

	for _, c := range cases {
		t.Run(c.Name, func(t *testing.T) {
			got, ok := timestampDiff(c.X, c.Y)
			if ok {
				t.Errorf("timestampDiff(%v, %v)=%v, want !ok", c.X, c.Y, got)
			}
		})
	}
}
