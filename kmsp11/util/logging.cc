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

#include "kmsp11/util/logging.h"

#include "absl/synchronization/mutex.h"
#include "glog/logging.h"
#include "grpc/support/log.h"
#include "kmsp11/util/errors.h"
#include "kmsp11/util/platform.h"
#include "kmsp11/util/status_utils.h"

namespace cloud_kms::kmsp11 {
namespace {

ABSL_CONST_INIT static absl::Mutex logging_lock(absl::kConstInit);
static bool logging_initialized ABSL_GUARDED_BY(logging_lock);

void GrpcLog(gpr_log_func_args* args) {
  // Map gRPC severities to glog severities.
  // gRPC severities: ERROR, INFO, DEBUG
  // glog severities: FATAL, ERROR, WARNING, INFO
  int severity;
  switch (args->severity) {
    // gRPC ERROR -> glog WARNING. gRPC errors aren't necessarily errors for
    // us; see e.g. https://github.com/grpc/grpc/issues/22613. We should emit
    // our own message at level ERROR for events that we consider errors.
    case GPR_LOG_SEVERITY_ERROR:
      severity = google::GLOG_WARNING;
      break;
    // gRPC INFO and gRPC DEBUG -> glog INFO. Note that, by default, gRPC will
    // not pass us messages at these levels. The GRPC_VERBOSITY environment
    // variable would need to be set.
    // https://github.com/grpc/grpc/blob/master/TROUBLESHOOTING.md#grpc_verbosity
    default:
      severity = google::GLOG_INFO;
      break;
  }

  google::LogMessage(args->file, args->line, severity).stream()
      << args->message;
}

}  // namespace

absl::Status InitializeLogging(std::string_view output_directory,
                               std::string_view output_filename_suffix) {
  absl::WriterMutexLock lock(&logging_lock);

  if (logging_initialized) {
    return NewInternalError("logging is already initialized", SOURCE_LOCATION);
  }

  if (output_directory.empty()) {
    google::SetStderrLogging(google::GLOG_INFO);
    // Disable discrete log files for all levels.
    for (google::LogSeverity severity :
         {google::GLOG_INFO, google::GLOG_WARNING, google::GLOG_ERROR,
          google::GLOG_FATAL}) {
      google::SetLogDestination(severity, "");
    }

  } else {
    // FATAL logs crash the program; emit these to standard error as well.
    google::SetStderrLogging(google::GLOG_FATAL);

    google::SetLogDestination(
        google::GLOG_INFO,
        absl::StrCat(output_directory, "/libkmsp11.log-").c_str());

    // Disable discrete log files for all levels but INFO -- they all still get
    // logged to the INFO logfile.
    for (google::LogSeverity severity :
         {google::GLOG_WARNING, google::GLOG_ERROR, google::GLOG_FATAL}) {
      google::SetLogDestination(severity, "");
    }

    if (!output_filename_suffix.empty()) {
      google::SetLogFilenameExtension(
          absl::StrCat(output_filename_suffix, "-").c_str());
    }
  }

  google::InitGoogleLogging("libkmsp11");
  gpr_set_log_function(&GrpcLog);
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

CK_RV LogAndResolve(std::string_view function_name,
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
    // standard error and to the syslog (on Posix) so that it lands /somewhere/.
    std::string preout_message = absl::StrCat(
        "kmsp11 failure occurred prior to library initialization: ", message);
    std::cerr << preout_message << std::endl;
    WriteToSystemLog(preout_message.c_str());
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

}  // namespace cloud_kms::kmsp11
