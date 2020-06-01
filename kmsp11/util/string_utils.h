#ifndef KMSP11_UTIL_STRING_UTILS_H_
#define KMSP11_UTIL_STRING_UTILS_H_

#include <cstdint>

#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "absl/time/time.h"
#include "absl/types/span.h"
#include "openssl/bn.h"

namespace kmsp11 {

// Constructs a new string by reinterepting `data` as chars.
//
// C-style arrays of unsigned chars are used extensively in BoringSSL for binary
// data, and in Cryptoki for both text and binary data. In memory that we own,
// std::string is the preferred storage form for both text and binary data.
inline std::string StrFromBytes(absl::Span<const uint8_t> data) {
  return std::string(reinterpret_cast<const char*>(data.data()), data.size());
}

// Replaces all content at `dest` by first copying the contents of `src`
// and then filling any remaining bytes with `pad_char`. Returns OutOfRangeError
// if `src.length()` is greater than `dest.length()`.
//
// This is a Cryptoki convention for filling character data in info structs.
// CK_INFO.manufacturerID is an example of a field that is filled this way:
// http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/errata01/os/pkcs11-base-v2.40-errata01-os-complete.html#_Toc235002241
absl::Status CryptokiStrCopy(absl::string_view src, absl::Span<uint8_t> dest,
                             char pad_char = ' ');

// Marshals an OpenSSL BIGNUM into the string format expected by Cryptoki.
// http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/pkcs11-base-v2.40.html#_Ref457115175
std::string MarshalBigNum(const BIGNUM* value);

// Marshals a boolean into the string format expected by Cryptoki. This is
// equivalent to a simple CK_CHAR conversion of 0x00 (false) or 0x01 (true).
// http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/pkcs11-base-v2.40.html#CK_BYTE
std::string MarshalBool(bool value);

// Marshals a date into the string format expected by Cryptoki.
// http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/pkcs11-base-v2.40.html#_Toc323024069
std::string MarshalDate(absl::Time value);

// Marshals an unsigned long int into the string format expected by Cryptoki.
// Note that this is platform-dependent, and is equivalent to a simple char*
// conversion of a CK_ULONG.
// http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/pkcs11-base-v2.40.html#_Toc441755771
std::string MarshalULong(unsigned long int value);

// Marshals a span of unsigned long ints into the string format expected by
// Cryptoki. Note that this is platform-dependent, and is equivalent to a simple
// char* conversion of a CK_ULONG*.
// http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/pkcs11-base-v2.40.html#_Toc225305959
std::string MarshalULongList(absl::Span<const unsigned long int> value);

}  // namespace kmsp11

#endif  // KMSP11_UTIL_STRING_UTILS_H_
