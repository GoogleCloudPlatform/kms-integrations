#include "kmsp11/util/logging.h"

#include <filesystem>
#include <fstream>

#include "absl/cleanup/cleanup.h"
#include "absl/strings/escaping.h"
#include "glog/logging.h"
#include "gmock/gmock.h"
#include "kmsp11/test/matchers.h"
#include "kmsp11/test/resource_helpers.h"
#include "kmsp11/test/test_status_macros.h"

namespace kmsp11 {
namespace {

using ::testing::HasSubstr;
using ::testing::IsEmpty;
using ::testing::Not;
using ::testing::SizeIs;
using ::testing::internal::CaptureStderr;
using ::testing::internal::GetCapturedStderr;

TEST(LoggingTest, NoDirectoryLogsInfoToStandardError) {
  CaptureStderr();
  ASSERT_OK(InitializeLogging("", ""));
  absl::Cleanup c = ShutdownLogging;

  std::string message = "Here is a sample message";
  LOG(INFO) << message;

  EXPECT_THAT(GetCapturedStderr(), HasSubstr(message));
}

TEST(LoggingTest, NoDirectoryLogsWarningToStandardError) {
  CaptureStderr();
  ASSERT_OK(InitializeLogging("", ""));
  absl::Cleanup c = ShutdownLogging;

  std::string message = "Here is a sample message";
  LOG(WARNING) << message;

  EXPECT_THAT(GetCapturedStderr(), HasSubstr(message));
}

TEST(LoggingTest, NoDirectoryLogsErrorToStandardError) {
  CaptureStderr();
  ASSERT_OK(InitializeLogging("", ""));
  absl::Cleanup c = ShutdownLogging;

  std::string message = "Here is a sample message";
  LOG(ERROR) << message;

  EXPECT_THAT(GetCapturedStderr(), HasSubstr(message));
}

TEST(LoggingTest, NoDirectoryLogsFatalToStandardError) {
  ASSERT_OK(InitializeLogging("", ""));
  absl::Cleanup c = ShutdownLogging;

  std::string message = "Here is a sample message";
  EXPECT_DEATH({ LOG(FATAL) << message; }, HasSubstr(message));
}

TEST(LoggingTest, FilenameSuffixIgnoredWhenNoDirectoryIsSpecified) {
  CaptureStderr();
  ASSERT_OK(InitializeLogging("", "foobar"));
  absl::Cleanup c = ShutdownLogging;

  std::string message = "Here is a sample message";
  LOG(ERROR) << message;
  EXPECT_THAT(GetCapturedStderr(), HasSubstr(message));
}

class LogDirectoryTest : public testing::Test {
 protected:
  void SetUp() override {
    log_directory_ =
        std::filesystem::temp_directory_path().append(RandomId()).string();
    ASSERT_TRUE(std::filesystem::create_directory(log_directory_));
  }

  void TearDown() override {
    std::error_code code;
    std::filesystem::remove_all(log_directory_, code);
    ASSERT_EQ(code.value(), 0);
  }

  std::vector<std::filesystem::directory_entry> LogDirectoryEntries() {
    std::filesystem::recursive_directory_iterator iter(log_directory_);
    return std::vector<std::filesystem::directory_entry>(
        std::filesystem::begin(iter), std::filesystem::end(iter));
  }

  std::string log_directory_;
};

TEST_F(LogDirectoryTest, DirectorySpecifiedDoesNotLogInfoToStandardError) {
  CaptureStderr();
  ASSERT_OK(InitializeLogging(log_directory_, ""));
  absl::Cleanup c = ShutdownLogging;

  LOG(INFO) << "Here is a sample message";

  EXPECT_THAT(GetCapturedStderr(), IsEmpty());
}

TEST_F(LogDirectoryTest, DirectorySpecifiedDoesNotLogWarningToStandardError) {
  CaptureStderr();
  ASSERT_OK(InitializeLogging(log_directory_, ""));
  absl::Cleanup c = ShutdownLogging;

  LOG(WARNING) << "Here is a sample message";

  EXPECT_THAT(GetCapturedStderr(), IsEmpty());
}

TEST_F(LogDirectoryTest, DirectorySpecifiedDoesNotLogErrorToStandardError) {
  CaptureStderr();
  ASSERT_OK(InitializeLogging(log_directory_, ""));
  absl::Cleanup c = ShutdownLogging;

  LOG(ERROR) << "Here is a sample message";

  EXPECT_THAT(GetCapturedStderr(), IsEmpty());
}

TEST_F(LogDirectoryTest, DirectorySpecifiedLogsFatalToStandardError) {
  ASSERT_OK(InitializeLogging(log_directory_, ""));
  absl::Cleanup c = ShutdownLogging;

  std::string message = "Here is a sample message";
  EXPECT_DEATH({ LOG(FATAL) << message; }, HasSubstr(message));
}

TEST_F(LogDirectoryTest, LogFilenameMatchesExpectedPattern) {
  ASSERT_OK(InitializeLogging(log_directory_, ""));
  absl::Cleanup c = ShutdownLogging;

  LOG(WARNING) << "Here is a sample message";

  std::vector<std::filesystem::directory_entry> files = LogDirectoryEntries();
  ASSERT_THAT(files, SizeIs(1));
  EXPECT_THAT(files[0].path().filename().string(),
              MatchesStdRegex("libkmsp11\\.log-\\d{8}-\\d{6}\\.\\d+"));
}

TEST_F(LogDirectoryTest, LogFilenameMatchesExpectedPatternWithSuffix) {
  ASSERT_OK(InitializeLogging(log_directory_, "foobar"));
  absl::Cleanup c = ShutdownLogging;

  LOG(ERROR) << "Here is a sample message";

  std::vector<std::filesystem::directory_entry> files = LogDirectoryEntries();
  ASSERT_THAT(files, SizeIs(1));
  EXPECT_THAT(files[0].path().filename().string(),
              MatchesStdRegex("libkmsp11\\.log-foobar-\\d{8}-\\d{6}\\.\\d+"));
}

TEST_F(LogDirectoryTest, SingleFileContainsAllLogLevels) {
  std::string info_message = "Info message";
  std::string warning_message = "Warning message";
  std::string error_message = "Error message";

  {
    // Using a separate scope to ensure logfiles are flushed.
    ASSERT_OK(InitializeLogging(log_directory_, ""));
    absl::Cleanup c = ShutdownLogging;

    LOG(INFO) << info_message;
    LOG(WARNING) << warning_message;
    LOG(ERROR) << error_message;
  }

  std::vector<std::filesystem::directory_entry> files = LogDirectoryEntries();
  ASSERT_THAT(files, SizeIs(1));
  std::ifstream in(files[0].path().string());
  std::string log_content((std::istreambuf_iterator<char>(in)),
                          (std::istreambuf_iterator<char>()));
  EXPECT_THAT(log_content,
              AllOf(HasSubstr(info_message), HasSubstr(warning_message),
                    HasSubstr(error_message)));
}

}  // namespace
}  // namespace kmsp11