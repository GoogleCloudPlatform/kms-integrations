#include "kmsp11/test/fakekms/cpp/fakekms.h"

#include "absl/time/clock.h"
#include "gmock/gmock.h"
#include "grpcpp/create_channel.h"
#include "grpcpp/security/credentials.h"
#include "kmsp11/test/test_status_macros.h"

namespace kmsp11 {
namespace {

TEST(CppFakeKmsTest, SmokeTest) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<FakeKms> fake, FakeKms::New());

  grpc::ChannelArguments args;
  std::shared_ptr<grpc::Channel> channel = grpc::CreateCustomChannel(
      fake->listen_addr(), grpc::InsecureChannelCredentials(), args);

  std::unique_ptr<kms_v1::KeyManagementService::Stub> stub =
      kms_v1::KeyManagementService::NewStub(channel);

  grpc::ClientContext ctx;

  kms_v1::CreateKeyRingRequest req;
  req.set_parent("projects/my-project/locations/us-central1");
  req.set_key_ring_id("kr1");

  kms_v1::KeyRing kr;

  EXPECT_OK(stub->CreateKeyRing(&ctx, req, &kr));
  EXPECT_EQ(kr.name(),
            "projects/my-project/locations/us-central1/keyRings/kr1");
}

TEST(CppFakeKmsTest, EnsureFlagsArePassed) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<FakeKms> fake,
                       FakeKms::New("-delay=3s"));

  grpc::ChannelArguments args;
  std::shared_ptr<grpc::Channel> channel = grpc::CreateCustomChannel(
      fake->listen_addr(), grpc::InsecureChannelCredentials(), args);

  std::unique_ptr<kms_v1::KeyManagementService::Stub> stub =
      kms_v1::KeyManagementService::NewStub(channel);

  grpc::ClientContext ctx;

  kms_v1::CreateKeyRingRequest req;
  req.set_parent("projects/my-project/locations/us-central1");
  req.set_key_ring_id("kr1");

  kms_v1::KeyRing kr;

  absl::Time begin = absl::Now();
  EXPECT_OK(stub->CreateKeyRing(&ctx, req, &kr));
  EXPECT_GE(absl::Now() - begin, absl::Seconds(3));
}

}  // namespace
}  // namespace kmsp11
