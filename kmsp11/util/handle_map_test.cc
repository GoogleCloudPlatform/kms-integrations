#include "kmsp11/util/handle_map.h"

#include "gtest/gtest.h"
#include "kmsp11/test/matchers.h"
#include "kmsp11/test/test_status_macros.h"
#include "kmsp11/util/errors.h"

namespace kmsp11 {
namespace {

using ::testing::ElementsAre;
using ::testing::UnorderedElementsAre;

TEST(HandleMapTest, ItemHandleValid) {
  HandleMap<int> map(CKR_SESSION_HANDLE_INVALID);

  CK_ULONG handle = map.Add(3);
  EXPECT_NE(handle, CK_INVALID_HANDLE);
}

TEST(HandleMapTest, ItemHandlesDifferent) {
  HandleMap<int> map(CKR_SESSION_HANDLE_INVALID);

  CK_ULONG handle1 = map.Add(3);
  CK_ULONG handle2 = map.Add(4);
  EXPECT_NE(handle1, handle2);
}

TEST(HandleMapTest, AllItemsAdded) {
  HandleMap<int> map(CKR_SESSION_HANDLE_INVALID);

  CK_ULONG handle1 = map.Add(3);
  CK_ULONG handle2 = map.Add(4);
  CK_ULONG handle3 = map.Add(5);

  EXPECT_THAT(map.Find([](int) { return true; }),
              UnorderedElementsAre(handle1, handle2, handle3));
}

TEST(HandleMapTest, AddDirectSuccess) {
  HandleMap<int> map(CKR_SESSION_HANDLE_INVALID);

  EXPECT_OK(map.AddDirect(1, std::make_shared<int>(3)));
  EXPECT_OK(map.AddDirect(2, std::make_shared<int>(2)));
  EXPECT_OK(map.AddDirect(3, std::make_shared<int>(1)));

  EXPECT_THAT(map.Find([](int) { return true; }),
              UnorderedElementsAre(1, 2, 3));
}

TEST(HandleMapTest, AddDirectInternalErrorOnDuplicateHandle) {
  HandleMap<int> map(CKR_SESSION_HANDLE_INVALID);

  EXPECT_OK(map.AddDirect(1, std::make_shared<int>(1)));
  EXPECT_THAT(map.AddDirect(1, std::make_shared<int>(2)),
              StatusIs(absl::StatusCode::kInternal,
                       testing::HasSubstr("handle 0x1 is already in use")));
}

TEST(HandleMapTest, FindPredicate) {
  HandleMap<int> map(CKR_SESSION_HANDLE_INVALID);

  map.Add(3);
  CK_ULONG handle2 = map.Add(4);
  map.Add(5);
  CK_ULONG handle4 = map.Add(6);

  EXPECT_THAT(map.Find([](int i) { return i % 2 == 0; }),
              UnorderedElementsAre(handle2, handle4));
}

TEST(HandleMapTest, FindWithSort) {
  HandleMap<int> map(CKR_SESSION_HANDLE_INVALID);

  CK_ULONG handle3 = map.Add(3);
  map.Add(4);
  CK_ULONG handle5 = map.Add(5);
  map.Add(6);
  CK_ULONG handle7 = map.Add(7);

  EXPECT_THAT(
      map.Find([](int i) { return i % 2 == 1; },
               [](const int& i1, const int& i2) -> bool { return i1 > i2; }),
      ElementsAre(handle7, handle5, handle3));
}

TEST(HandleMapTest, GetByHandle) {
  HandleMap<int> map(CKR_SESSION_HANDLE_INVALID);

  CK_ULONG handle = map.Add(3);

  ASSERT_OK_AND_ASSIGN(std::shared_ptr<int> value, map.Get(handle));
  EXPECT_EQ(*value, 3);
}

TEST(HandleMapTest, GetInvalidHandle) {
  HandleMap<int> map(CKR_SESSION_HANDLE_INVALID);

  EXPECT_THAT(map.Get(1), StatusRvIs(CKR_SESSION_HANDLE_INVALID));
}

TEST(HandleMapTest, RemoveRemoves) {
  HandleMap<int> map(CKR_SESSION_HANDLE_INVALID);

  CK_ULONG handle = map.Add(3);
  EXPECT_OK(map.Remove(handle));

  EXPECT_THAT(map.Get(handle), StatusRvIs(CKR_SESSION_HANDLE_INVALID));
}

TEST(HandleMapTest, RemoveInvalidHandle) {
  HandleMap<int> map(CKR_SESSION_HANDLE_INVALID);

  EXPECT_THAT(map.Remove(5), StatusRvIs(CKR_SESSION_HANDLE_INVALID));
}

}  // namespace
}  // namespace kmsp11