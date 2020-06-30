#include "kmsp11/util/logging.h"

#include "absl/synchronization/mutex.h"
#include "glog/logging.h"
#include "kmsp11/util/errors.h"
#include "kmsp11/util/status_utils.h"

namespace kmsp11 {
namespace {

ABSL_CONST_INIT static absl::Mutex logging_lock(absl::kConstInit);
static bool logging_initialized ABSL_GUARDED_BY(logging_lock);

}  // namespace

absl::Status InitializeLogging(absl::string_view output_directory) {
  absl::WriterMutexLock lock(&logging_lock);

  if (logging_initialized) {
    return NewInternalError("logging is already initialized", SOURCE_LOCATION);
  }

  // Always set both of these properties, in case the library is re-initialized
  // with new configuration.
  FLAGS_log_dir = std::string(output_directory);
  FLAGS_logtostderr = output_directory.empty();

  google::InitGoogleLogging("libkmsp11");
  logging_initialized = true;
  return absl::OkStatus();
}

void ShutdownLogging() {
  absl::WriterMutexLock lock(&logging_lock);
  if (logging_initialized) {
    google::ShutdownGoogleLogging();
    logging_initialized = false;
  }
}

CK_RV LogAndResolve(absl::string_view function_name,
                    const absl::Status& status) {
  if (status.ok()) {
    return CKR_OK;
  }

  CK_RV rv = GetCkRv(status);
  std::string message =
      absl::StrFormat("returning %#x from %s due to status %s", rv,
                      function_name, status.ToString());

  absl::ReaderMutexLock lock(&logging_lock);

  if (!logging_initialized) {
    // This failure occurred before library initialization. Write output to
    // standard error so that it lands /somewhere/.
    std::cerr << "kmsp11 failure occurred prior to library initialization: "
              << message << std::endl;
    return rv;
  }

  if (absl::IsInternal(status)) {
    // Internal statuses mean some library assumption was violated, so treat
    // this more severely than a business error.
    LOG(ERROR) << message;
    return rv;
  }

  // Treat all other non-OK statuses as business errors.
  LOG(INFO) << message;
  return rv;
}

}  // namespace kmsp11
