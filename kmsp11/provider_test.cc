#include "kmsp11/provider.h"

#include "gmock/gmock.h"
#include "kmsp11/test/matchers.h"
#include "kmsp11/test/test_status_macros.h"
#include "kmsp11/util/string_utils.h"

namespace kmsp11 {
namespace {

using ::testing::AllOf;
using ::testing::Eq;
using ::testing::Field;
using ::testing::Le;

class InfoTest : public testing::Test {
 protected:
  inline void SetUp() override {
    ASSERT_OK_AND_ASSIGN(Provider provider, Provider::New());
    info_ = provider.info();
  }

  CK_INFO info_;
};

TEST_F(InfoTest, CryptokiVersionIsSet) {
  EXPECT_THAT(
      info_.cryptokiVersion,
      AllOf(Field("major", &CK_VERSION::major, Eq(CRYPTOKI_VERSION_MAJOR)),
            Field("minor", &CK_VERSION::minor, Eq(CRYPTOKI_VERSION_MINOR))));
}

TEST_F(InfoTest, ManufacturerIdIsSet) {
  EXPECT_EQ(StrFromBytes(info_.manufacturerID),
            // Note the space-padding to get to 32 characters
            "Google                          ");
}

TEST_F(InfoTest, FlagsIsZero) { EXPECT_THAT(info_.flags, Eq(0)); }

TEST_F(InfoTest, LibraryDescriptionIsSet) {
  EXPECT_THAT(StrFromBytes(info_.libraryDescription),
              // Note the space-padding to get to 32 characters
              "Cryptoki Library for Cloud KMS  ");
}

TEST_F(InfoTest, LibraryVersionIsSet) {
  EXPECT_THAT(info_.libraryVersion,
              AllOf(Field("major", &CK_VERSION::major, Le(10)),
                    Field("minor", &CK_VERSION::minor, Le(100))));
}

}  // namespace
}  // namespace kmsp11
