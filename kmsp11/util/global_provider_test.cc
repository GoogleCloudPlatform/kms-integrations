#include "kmsp11/util/global_provider.h"

#include "gmock/gmock.h"
#include "kmsp11/test/matchers.h"
#include "kmsp11/test/test_status_macros.h"
#include "kmsp11/util/cleanup.h"

namespace kmsp11 {
namespace {

using ::testing::AllOf;
using ::testing::HasSubstr;
using ::testing::IsNull;

TEST(GlobalProviderTest, GetProviderBeforeSetReturnsNullptr) {
  EXPECT_THAT(GetGlobalProvider(), IsNull());
}

TEST(GlobalProviderTest, GetProviderAfterSetReturnsProvider) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<Provider> provider,
                       Provider::New(LibraryConfig()));
  Provider* captured_provider = provider.get();

  ASSERT_OK(SetGlobalProvider(std::move(provider)));
  Cleanup c([]() { ASSERT_OK(ReleaseGlobalProvider()); });

  EXPECT_EQ(GetGlobalProvider(), captured_provider);
}

TEST(GlobalProviderTest, SetProviderToNullReturnsError) {
  EXPECT_THAT(SetGlobalProvider(nullptr),
              AllOf(StatusIs(absl::StatusCode::kInternal, HasSubstr("nullptr")),
                    StatusRvIs(CKR_GENERAL_ERROR)));
}

TEST(GlobalProviderTest, SetProviderWhenAlreadySetReturnsError) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<Provider> provider1,
                       Provider::New(LibraryConfig()));
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<Provider> provider2,
                       Provider::New(LibraryConfig()));

  ASSERT_OK(SetGlobalProvider(std::move(provider1)));
  Cleanup c([]() { ASSERT_OK(ReleaseGlobalProvider()); });

  EXPECT_THAT(SetGlobalProvider(std::move(provider2)),
              AllOf(StatusIs(absl::StatusCode::kInternal,
                             HasSubstr("provider has already been set")),
                    StatusRvIs(CKR_GENERAL_ERROR)));
}

TEST(GlobalProviderTest, GetProviderAfterReleaseReturnsNullptr) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<Provider> provider,
                       Provider::New(LibraryConfig()));

  ASSERT_OK(SetGlobalProvider(std::move(provider)));
  ASSERT_OK(ReleaseGlobalProvider());

  EXPECT_THAT(GetGlobalProvider(), IsNull());
}

TEST(GlobalProviderTest, SetAndGetProviderAfterReleaseReturnsProvider) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<Provider> provider1,
                       Provider::New(LibraryConfig()));
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<Provider> provider2,
                       Provider::New(LibraryConfig()));
  Provider* captured_provider2 = provider2.get();

  ASSERT_OK(SetGlobalProvider(std::move(provider1)));
  ASSERT_OK(ReleaseGlobalProvider());
  ASSERT_OK(SetGlobalProvider(std::move(provider2)))
  Cleanup c([]() { ASSERT_OK(ReleaseGlobalProvider()); });

  EXPECT_EQ(GetGlobalProvider(), captured_provider2);
}

}  // namespace
}  // namespace kmsp11