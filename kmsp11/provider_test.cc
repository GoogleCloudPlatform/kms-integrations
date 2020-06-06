#include "kmsp11/provider.h"

#include "gmock/gmock.h"
#include "kmsp11/test/fakekms/cpp/fakekms.h"
#include "kmsp11/test/matchers.h"
#include "kmsp11/test/proto_parser.h"
#include "kmsp11/test/resource_helpers.h"
#include "kmsp11/test/test_status_macros.h"
#include "kmsp11/util/string_utils.h"

namespace kmsp11 {
namespace {

using ::testing::AllOf;
using ::testing::Eq;
using ::testing::Field;
using ::testing::Le;

class ProviderTest : public testing::Test {
 protected:
  void SetUp() override {
    ASSERT_OK_AND_ASSIGN(fake_kms_, FakeKms::New());

    auto client = fake_kms_->NewClient();
    kms_v1::KeyRing kr1;
    kr1 = CreateKeyRingOrDie(client.get(), kTestLocation, RandomId(), kr1);
    kms_v1::KeyRing kr2;
    kr2 = CreateKeyRingOrDie(client.get(), kTestLocation, RandomId(), kr2);

    LibraryConfig config = ParseTestProto(
        absl::StrFormat(R"(
      tokens {
        key_ring: "%s"
        label: "foo"
      }
      tokens {
        key_ring: "%s"
        label: "bar"
      }
      kms_endpoint: "%s",
      use_insecure_grpc_channel_credentials: true,
    )",
                        kr1.name(), kr2.name(), fake_kms_->listen_addr()));

    ASSERT_OK_AND_ASSIGN(provider_, Provider::New(config));
    info_ = provider_->info();
  }

  std::unique_ptr<FakeKms> fake_kms_;
  std::unique_ptr<Provider> provider_;
  CK_INFO info_;
};

TEST_F(ProviderTest, InfoCryptokiVersionIsSet) {
  EXPECT_THAT(
      info_.cryptokiVersion,
      AllOf(Field("major", &CK_VERSION::major, Eq(CRYPTOKI_VERSION_MAJOR)),
            Field("minor", &CK_VERSION::minor, Eq(CRYPTOKI_VERSION_MINOR))));
}

TEST_F(ProviderTest, InfoManufacturerIdIsSet) {
  EXPECT_EQ(StrFromBytes(info_.manufacturerID),
            // Note the space-padding to get to 32 characters
            "Google                          ");
}

TEST_F(ProviderTest, InfoFlagsIsZero) { EXPECT_THAT(info_.flags, Eq(0)); }

TEST_F(ProviderTest, LibraryDescriptionIsSet) {
  EXPECT_THAT(StrFromBytes(info_.libraryDescription),
              // Note the space-padding to get to 32 characters
              "Cryptoki Library for Cloud KMS  ");
}

TEST_F(ProviderTest, InfoLibraryVersionIsSet) {
  EXPECT_THAT(info_.libraryVersion,
              AllOf(Field("major", &CK_VERSION::major, Le(10)),
                    Field("minor", &CK_VERSION::minor, Le(100))));
}

TEST_F(ProviderTest, ConfiguredTokens) {
  EXPECT_EQ(provider_->token_count(), 2);

  ASSERT_OK_AND_ASSIGN(const Token* token0, provider_->TokenAt(0));
  EXPECT_THAT(StrFromBytes(token0->token_info().label),
              MatchesStdRegex("foo[ ]+"));

  ASSERT_OK_AND_ASSIGN(const Token* token1, provider_->TokenAt(1));
  EXPECT_THAT(StrFromBytes(token1->token_info().label),
              MatchesStdRegex("bar[ ]+"));
}

}  // namespace
}  // namespace kmsp11
