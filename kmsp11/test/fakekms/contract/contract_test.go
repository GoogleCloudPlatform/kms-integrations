// Package contract implements contract tests for fakekms
// go/mocks#fakes-need-tests
package contract

import (
	"context"
	"flag"
	"log"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"google.golang.org/api/option"
	"google.golang.org/grpc"

	"oss-tools/kmsp11/test/fakekms"

	kms "cloud.google.com/go/kms/apiv1"
)

// variables used by test cases
var (
	client   *kms.KeyManagementClient
	location string
)

func TestMain(m *testing.M) {
	flag.StringVar(&location, "location", "projects/fakekms-testing/locations/us-east1",
		"the project and location to use for testing")
	realKMS := flag.Bool("realkms", false,
		"true if tests should be run against real KMS instead of fakekms")
	credsFilePath := flag.String("credentials_file", "",
		"the google application credentials file to use for authentication; ignored for fake runs")
	flag.Parse()

	if *realKMS {
		testRealKMS(m, *credsFilePath)
	} else {
		testFakeKMS(m)
	}
}

func testRealKMS(m *testing.M, credsFilePath string) {
	initCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var opts []option.ClientOption
	if credsFilePath != "" {
		opts = append(opts, option.WithCredentialsFile(credsFilePath))
	}

	var err error
	client, err = kms.NewKeyManagementClient(initCtx, opts...)
	if err != nil {
		log.Fatalf("error creating KMS client: %v", err)
	}
	defer client.Close()

	os.Exit(m.Run())
}

func testFakeKMS(m *testing.M) {
	s, err := fakekms.NewServer()
	if err != nil {
		log.Fatal(err)
	}
	defer s.Close()

	cc, err := grpc.Dial(s.Addr.String(), grpc.WithInsecure())
	if err != nil {
		log.Fatalf("error opening gRPC client connection to fakekms: %v", err)
	}

	initCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	client, err = kms.NewKeyManagementClient(initCtx, option.WithGRPCConn(cc))
	if err != nil {
		log.Fatalf("error creating KMS client: %v", err)
	}
	defer client.Close()

	os.Exit(m.Run())
}

func randomID(t *testing.T) string {
	t.Helper()
	id, err := uuid.NewRandom()
	if err != nil {
		t.Fatal(err)
	}
	return id.String()
}
