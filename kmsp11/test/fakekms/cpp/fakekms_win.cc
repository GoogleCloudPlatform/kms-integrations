#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include "absl/strings/str_cat.h"
#include "absl/strings/str_format.h"
#include "glog/logging.h"
#include "kmsp11/test/fakekms/cpp/fakekms.h"
#include "kmsp11/test/runfiles.h"
#include "kmsp11/util/cleanup.h"
#include "kmsp11/util/status_macros.h"

namespace kmsp11 {

namespace {

class WindowsFakeKms : public FakeKms {
 public:
  static absl::StatusOr<std::unique_ptr<WindowsFakeKms>> New(
      absl::string_view flags);

  WindowsFakeKms(std::string listen_addr, HANDLE process_handle)
      : FakeKms(listen_addr), process_handle_(process_handle) {}

  ~WindowsFakeKms() {
    CHECK(TerminateProcess(process_handle_, 0));
    CHECK(CloseHandle(process_handle_));
  }

 private:
  HANDLE process_handle_;
};

absl::Status Win32ErrorToStatus(absl::string_view message) {
  char* error_text = nullptr;
  DWORD error_code = GetLastError();

  FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
                     FORMAT_MESSAGE_IGNORE_INSERTS,
                 nullptr, error_code, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                 error_text, 0, nullptr);

  return absl::InternalError(
      absl::StrFormat("%s: code %d: %s", message, error_code, error_text));
}

absl::StatusOr<std::unique_ptr<WindowsFakeKms>> WindowsFakeKms::New(
    absl::string_view flags) {
  // https://docs.microsoft.com/en-us/windows/win32/procthread/creating-a-child-process-with-redirected-input-and-output
  SECURITY_ATTRIBUTES security_attrs{
      sizeof(SECURITY_ATTRIBUTES),  // nLength
      nullptr,                      // lpSecurityDescriptor
      true,                         // bInheritHandle
  };

  HANDLE out_read, out_write;
  if (!CreatePipe(&out_read, &out_write, &security_attrs, 0)) {
    return Win32ErrorToStatus("error creating output pipe");
  }
  Cleanup c([&] {
    CHECK(CloseHandle(out_read));
    CHECK(CloseHandle(out_write));
  });

  STARTUPINFOA startup_info;
  ZeroMemory(&startup_info, sizeof(STARTUPINFOA));
  startup_info.cb = sizeof(STARTUPINFOA);
  startup_info.hStdOutput = out_write;
  startup_info.dwFlags = STARTF_USESTDHANDLES;

  PROCESS_INFORMATION process_info;

  std::string bin_path = RunfileLocation(
      "com_google_kmstools/kmsp11/test/fakekms/main/fakekms_/fakekms.exe");
  std::string command_line = absl::StrCat(bin_path, " ", flags);

  if (!CreateProcessA(bin_path.c_str(), const_cast<char*>(command_line.c_str()),
                      nullptr, nullptr, true, CREATE_NO_WINDOW, nullptr,
                      nullptr, &startup_info, &process_info)) {
    return Win32ErrorToStatus("error creating fakekms process");
  }
  CHECK(CloseHandle(process_info.hThread));  // we don't use this handle

  const size_t kBufferSize = 4096;  // should be enough to hold the listen addr
  char buf[kBufferSize];
  DWORD len;
  if (!ReadFile(out_read, buf, kBufferSize, &len, nullptr)) {
    return Win32ErrorToStatus("error reading listen address");
  }

  std::string address(buf, len);
  return absl::make_unique<WindowsFakeKms>(address, process_info.hProcess);
}

}  // namespace

absl::StatusOr<std::unique_ptr<FakeKms>> FakeKms::New(absl::string_view flags) {
  ASSIGN_OR_RETURN(std::unique_ptr<WindowsFakeKms> fake,
                   WindowsFakeKms::New(flags));
  return std::unique_ptr<FakeKms>(std::move(fake));
}

}  // namespace kmsp11