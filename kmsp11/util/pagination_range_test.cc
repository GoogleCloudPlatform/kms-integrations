// Copyright 2021 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// This file was ported from the Google Cloud Platform C++ Client Libraries,
// the original source can be found here:
// https://github.com/googleapis/google-cloud-cpp/blob/9d9591913f342bafcd83a34df8e96d4dd5d87534/google/cloud/internal/pagination_range_test.cc
#include "kmsp11/util/pagination_range.h"

#include "absl/status/status.h"
#include "gmock/gmock.h"
#include "google/bigtable/admin/v2/bigtable_instance_admin.grpc.pb.h"
#include "kmsp11/test/matchers.h"

namespace kmsp11 {
namespace {

using ::testing::_;
using ::testing::ElementsAre;
using ::testing::HasSubstr;
using ItemType = ::google::bigtable::admin::v2::AppProfile;
using Request = ::google::bigtable::admin::v2::ListAppProfilesRequest;
using Response = ::google::bigtable::admin::v2::ListAppProfilesResponse;
using TestedRange = PaginationRange<ItemType, Request, Response>;

class MockRpc {
 public:
  MOCK_METHOD1(Loader, absl::StatusOr<Response>(Request const&));
  MOCK_METHOD1(GetItems, std::vector<ItemType>(Response));
};

std::vector<ItemType> GetItems(Response const& response) {
  return std::vector<ItemType>(response.app_profiles().begin(),
                               response.app_profiles().end());
}

TEST(RangeFromPagination, Empty) {
  MockRpc mock;
  EXPECT_CALL(mock, Loader(_)).WillOnce([](Request const& request) {
    EXPECT_TRUE(request.page_token().empty());
    Response response;
    response.clear_next_page_token();
    return response;
  });

  TestedRange range(
      Request{}, [&](Request const& r) { return mock.Loader(r); }, GetItems);
  EXPECT_TRUE(range.begin() == range.end());
}

TEST(RangeFromPagination, SinglePage) {
  MockRpc mock;
  EXPECT_CALL(mock, Loader(_)).WillOnce([](Request const& request) {
    EXPECT_TRUE(request.page_token().empty());
    Response response;
    response.clear_next_page_token();
    response.add_app_profiles()->set_name("p1");
    response.add_app_profiles()->set_name("p2");
    return response;
  });

  TestedRange range(
      Request{}, [&](Request const& r) { return mock.Loader(r); }, GetItems);
  std::vector<std::string> names;
  for (auto& p : range) {
    if (!p.ok()) break;
    names.push_back(p->name());
  }
  EXPECT_THAT(names, ElementsAre("p1", "p2"));
}

TEST(RangeFromPagination, NonProtoRange) {
  MockRpc mock;
  EXPECT_CALL(mock, Loader(_)).WillOnce([](Request const& request) {
    EXPECT_TRUE(request.page_token().empty());
    Response response;
    response.clear_next_page_token();
    response.add_app_profiles()->set_name("p1");
    response.add_app_profiles()->set_name("p2");
    return response;
  });

  using NonProtoRange = PaginationRange<std::string, Request, Response>;

  NonProtoRange range(
      Request{}, [&](Request const& r) { return mock.Loader(r); },
      [](Response const& r) {
        std::vector<std::string> items;
        for (auto const& i : r.app_profiles()) {
          items.push_back(i.name());
        }
        return items;
      });
  std::vector<std::string> names;
  for (auto& p : range) {
    if (!p.ok()) break;
    names.push_back(*p);
  }
  EXPECT_THAT(names, ElementsAre("p1", "p2"));
}

TEST(RangeFromPagination, TwoPages) {
  MockRpc mock;
  EXPECT_CALL(mock, Loader(_))
      .WillOnce([](Request const& request) {
        EXPECT_TRUE(request.page_token().empty());
        Response response;
        response.set_next_page_token("t1");
        response.add_app_profiles()->set_name("p1");
        response.add_app_profiles()->set_name("p2");
        return response;
      })
      .WillOnce([](Request const& request) {
        EXPECT_EQ(request.page_token(), "t1");
        Response response;
        response.clear_next_page_token();
        response.add_app_profiles()->set_name("p3");
        response.add_app_profiles()->set_name("p4");
        return response;
      });

  TestedRange range(
      Request{}, [&](Request const& r) { return mock.Loader(r); }, GetItems);
  std::vector<std::string> names;
  for (auto& p : range) {
    if (!p.ok()) break;
    names.push_back(p->name());
  }
  EXPECT_THAT(names, ElementsAre("p1", "p2", "p3", "p4"));
}

TEST(RangeFromPagination, TwoPagesWithError) {
  MockRpc mock;
  EXPECT_CALL(mock, Loader(_))
      .WillOnce([](Request const& request) {
        EXPECT_TRUE(request.page_token().empty());
        Response response;
        response.set_next_page_token("t1");
        response.add_app_profiles()->set_name("p1");
        response.add_app_profiles()->set_name("p2");
        return response;
      })
      .WillOnce([](Request const& request) {
        EXPECT_EQ(request.page_token(), "t1");
        Response response;
        response.set_next_page_token("t2");
        response.add_app_profiles()->set_name("p3");
        response.add_app_profiles()->set_name("p4");
        return response;
      })
      .WillOnce([](Request const& request) {
        EXPECT_EQ(request.page_token(), "t2");
        return absl::AbortedError("bad-luck");
      });

  TestedRange range(
      Request{}, [&](Request const& r) { return mock.Loader(r); }, GetItems);
  std::vector<std::string> names;
  for (auto& p : range) {
    if (!p.ok()) {
      EXPECT_EQ(p.status().code(), absl::StatusCode::kAborted);
      EXPECT_THAT(p.status().message(), HasSubstr("bad-luck"));
      break;
    }
    names.push_back(p->name());
  }
  EXPECT_THAT(names, ElementsAre("p1", "p2", "p3", "p4"));
}

TEST(RangeFromPagination, IteratorCoverage) {
  MockRpc mock;
  EXPECT_CALL(mock, Loader(_))
      .WillOnce([](Request const& request) {
        EXPECT_TRUE(request.page_token().empty());
        Response response;
        response.set_next_page_token("t1");
        response.add_app_profiles()->set_name("p1");
        return response;
      })
      .WillOnce([](Request const& request) {
        EXPECT_EQ(request.page_token(), "t1");
        return absl::AbortedError("bad-luck");
      });

  TestedRange range(
      Request{}, [&](Request const& r) { return mock.Loader(r); }, GetItems);
  auto i0 = range.begin();
  auto i1 = i0;
  EXPECT_TRUE(i0 == i1);
  EXPECT_FALSE(i1 == range.end());
  ++i1;
  auto i2 = i1;
  EXPECT_FALSE(i0 == i1);
  EXPECT_TRUE(i1 == i2);
  ASSERT_FALSE(i1 == range.end());
  auto& item = *i1;
  EXPECT_EQ(item.status().code(), absl::StatusCode::kAborted);
  EXPECT_THAT(item.status().message(), HasSubstr("bad-luck"));
  ++i1;
  EXPECT_TRUE(i1 == range.end());
}

TEST(RangeFromPagination, Unimplemented) {
  using NonProtoRange = PaginationRange<std::string, Request, Response>;

  NonProtoRange range = UnimplementedPaginationRange<NonProtoRange>::Create();
  auto i = range.begin();
  EXPECT_NE(i, range.end());
  EXPECT_THAT(*i, kmsp11::StatusIs(absl::StatusCode::kUnimplemented));
}

}  // namespace
}  // namespace kmsp11
