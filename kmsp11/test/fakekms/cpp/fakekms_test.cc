#include "kmsp11/test/fakekms/cpp/fakekms.h"

#include "gmock/gmock.h"
#include "google/cloud/kms/v1/resources.pb.h"
#include "google/cloud/kms/v1/service.grpc.pb.h"
#include "google/cloud/kms/v1/service.pb.h"
#include "grpcpp/create_channel.h"
#include "grpcpp/security/credentials.h"
#include "kmsp11/test/test_status_macros.h"

namespace kmsp11 {
namespace {

namespace kms_v1 = ::google::cloud::kms::v1;

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

  EXPECT_TRUE(stub->CreateKeyRing(&ctx, req, &kr).ok());
  EXPECT_EQ(kr.name(),
            "projects/my-project/locations/us-central1/keyRings/kr1");
}

}  // namespace
}  // namespace kmsp11
