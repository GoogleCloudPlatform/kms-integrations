#include "kmsp11/util/string_utils.h"

#include "absl/strings/str_format.h"
#include "kmsp11/util/errors.h"

namespace kmsp11 {

absl::Status CryptokiStrCopy(absl::string_view src, absl::Span<uint8_t> dest,
                             char pad_char) {
  if (src.length() > dest.length()) {
    return NewError(
        absl::StatusCode::kOutOfRange,
        absl::StrFormat("\"%s\".length()=%d, want <= dest.length()=%d", src,
                        src.length(), dest.length()),
        CKR_FUNCTION_FAILED, SOURCE_LOCATION);
  }
  uint8_t* pos = std::copy(src.begin(), src.end(), dest.begin());
  std::fill(pos, dest.end(), pad_char);
  return absl::OkStatus();
}

}  // namespace kmsp11
