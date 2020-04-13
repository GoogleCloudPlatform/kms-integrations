#include "kmsp11/util/string_utils.h"

#include "absl/strings/str_format.h"

namespace kmsp11 {

absl::Status CryptokiStrCopy(absl::string_view src, absl::Span<uint8_t> dest,
                             char pad_char) {
  if (src.length() > dest.length()) {
    // TODO(bdhess): Add SourceLocation when it lands.
    return absl::OutOfRangeError(
        absl::StrFormat("\"%s\".length()=%d, want <= dest.length()=%d", src,
                        src.length(), dest.length()));
  }
  uint8_t* pos = std::copy(src.begin(), src.end(), dest.begin());
  std::fill(pos, dest.end(), pad_char);
  return absl::OkStatus();
}

}  // namespace kmsp11
