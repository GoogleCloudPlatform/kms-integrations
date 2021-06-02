/*
 * Copyright 2021 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef KMSP11_OPERATION_FIND_H_
#define KMSP11_OPERATION_FIND_H_

#include <vector>

#include "absl/types/span.h"
#include "kmsp11/cryptoki.h"

namespace kmsp11 {

// FindOp models a PKCS #11 Find operation.
//
// A FindOp is created at C_FindObjectsInit time, and is populated with all of
// the objects that match the provided attribute template. Calls to
// C_FindObjects deplete handles from the return set.
class FindOp {
 public:
  FindOp(std::vector<CK_OBJECT_HANDLE> objects)
      : objects_(objects), offset_(0) {}

  // Retrieves the next set of handles, up to max_count, and increments offset_
  // appropriately.
  inline absl::Span<const CK_OBJECT_HANDLE> Next(size_t max_count) {
    size_t remaining_count = objects_.size() - offset_;
    if (remaining_count <= max_count) {
      absl::Span<const CK_OBJECT_HANDLE> result(&objects_[offset_],
                                                remaining_count);
      offset_ = objects_.size();
      return result;
    }

    absl::Span<const CK_OBJECT_HANDLE> result(&objects_[offset_], max_count);
    offset_ += max_count;
    return result;
  }

 private:
  std::vector<CK_OBJECT_HANDLE> objects_;
  size_t offset_;
};

}  // namespace kmsp11

#endif  // KMSP11_OPERATION_FIND_H_
