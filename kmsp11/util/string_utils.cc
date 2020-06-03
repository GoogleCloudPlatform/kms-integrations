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

std::string MarshalBigNum(const BIGNUM* value) {
  std::string s;
  s.resize(BN_num_bytes(value));
  BN_bn2bin(value, reinterpret_cast<uint8_t*>(const_cast<char*>(s.data())));
  return s;
}

std::string MarshalBool(bool value) { return std::string(1, value); }

std::string MarshalDate(absl::Time value) {
  return absl::FormatTime("%E4Y%m%d", value, absl::UTCTimeZone());
}

std::string MarshalULong(unsigned long int value) {
  return std::string(reinterpret_cast<const char*>(&value),
                     sizeof(unsigned long int));
}

std::string MarshalULongList(absl::Span<const unsigned long int> value) {
  return std::string(reinterpret_cast<const char*>(value.data()),
                     value.size() * sizeof(unsigned long int));
}

}  // namespace kmsp11
