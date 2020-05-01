#ifndef KMSP11_UTIL_CLEANUP_H_
#define KMSP11_UTIL_CLEANUP_H_

#include <functional>

namespace kmsp11 {

// A convenience helper for RAII-style cleanups.
class Cleanup {
 public:
  Cleanup(std::function<void()> f) : f_(f) {}
  ~Cleanup() { f_(); }

 private:
  std::function<void()> f_;
};

}  // namespace kmsp11

#endif  // KMSP11_UTIL_CLEANUP_H_
