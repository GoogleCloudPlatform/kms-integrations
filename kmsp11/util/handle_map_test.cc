#include "kmsp11/util/handle_map.h"

#include "gtest/gtest.h"
#include "kmsp11/test/matchers.h"
#include "kmsp11/test/test_status_macros.h"
#include "kmsp11/util/errors.h"

namespace kmsp11 {
namespace {

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

TEST(HandleMapTest, FindPredicate) {
  HandleMap<int> map(CKR_SESSION_HANDLE_INVALID);

  map.Add(3);
  CK_ULONG handle2 = map.Add(4);
  map.Add(5);
  CK_ULONG handle4 = map.Add(6);

  EXPECT_THAT(map.Find([](int i) { return i % 2 == 0; }),
              UnorderedElementsAre(handle2, handle4));
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