#ifndef KMSP11_UTIL_HANDLE_MAP_H_
#define KMSP11_UTIL_HANDLE_MAP_H_

#include <limits>

#include "absl/container/flat_hash_map.h"
#include "absl/random/random.h"
#include "kmsp11/cryptoki.h"
#include "kmsp11/util/errors.h"
#include "kmsp11/util/status_or.h"

namespace kmsp11 {

// A HandleMap contains a set of items with assigned CK_ULONG handles.
// It is intended for use with the PKCS #11 Session and Object types, both
// of which are identified by a handle.
template <typename T>
class HandleMap {
 public:
  // Create a new map. The provided CK_RV will be used for Get and Remove
  // operations performed against an unknown handle.
  HandleMap(CK_RV not_found_rv) : not_found_rv_(not_found_rv) {}

  // Adds item to the map and returns its handle.
  inline CK_ULONG Add(T&& item) {
    absl::WriterMutexLock lock(&mutex_);

    // Generate a new handle by picking a random number in the range [1,
    // max(ULONG)] and ensuring that it is not already in use. Repeat this
    // process until we have a useable handle. We start from 1 because 0 is
    // CK_INVALID_HANDLE.
    CK_ULONG handle;
    do {
      handle = absl::Uniform<CK_ULONG>(bit_gen_, 1,
                                       std::numeric_limits<CK_ULONG>::max());
    } while (items_.contains(handle));

    items_.try_emplace(handle, std::make_shared<T>(std::move(item)));
    return handle;
  }

  // Finds all keys in the map whose value matches the provided predicate.
  inline std::vector<CK_ULONG> Find(std::function<bool(const T&)> predicate) {
    absl::ReaderMutexLock lock(&mutex_);

    std::vector<CK_ULONG> results;
    for (auto it : items_) {
      if (predicate(*it.second)) {
        results.push_back(it.first);
      }
    }
    return results;
  }

  // Gets the map element with the provided handle, or returns NotFound if there
  // is no element with the provided handle.
  inline StatusOr<std::shared_ptr<T>> Get(CK_ULONG handle) {
    absl::ReaderMutexLock lock(&mutex_);

    auto it = items_.find(handle);
    if (it == items_.end()) {
      return HandleNotFoundError(handle, SOURCE_LOCATION);
    }

    return it->second;
  }

  // Removes the map element with the provided handle, or returns NotFound if
  // there is no element with the provided handle.
  inline absl::Status Remove(CK_ULONG handle) {
    absl::WriterMutexLock lock(&mutex_);

    auto it = items_.find(handle);
    if (it == items_.end()) {
      return HandleNotFoundError(handle, SOURCE_LOCATION);
    }

    items_.erase(it);
    return absl::OkStatus();
  }

 private:
  CK_RV not_found_rv_;
  absl::Mutex mutex_;
  absl::BitGen bit_gen_ ABSL_GUARDED_BY(mutex_);
  absl::flat_hash_map<CK_ULONG, std::shared_ptr<T>> items_
      ABSL_GUARDED_BY(mutex_);

  inline absl::Status HandleNotFoundError(
      CK_ULONG handle, const SourceLocation& source_location) {
    return NewError(absl::StatusCode::kNotFound,
                    absl::StrFormat("handle not found: %#x", handle),
                    not_found_rv_, SOURCE_LOCATION);
  }
};

}  // namespace kmsp11

#endif  // KMSP11_UTIL_HANDLE_MAP_H_
