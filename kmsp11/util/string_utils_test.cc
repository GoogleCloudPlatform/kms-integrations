#include "kmsp11/util/string_utils.h"

#include "absl/strings/str_cat.h"
#include "absl/types/span.h"
#include "gmock/gmock.h"
#include "kmsp11/test/matchers.h"

namespace kmsp11 {
namespace {

using ::testing::ElementsAre;

TEST(StrFromBytesTest, DecodeTextData) {
  uint8_t bytes[4] = {0x41, 0x42, 0x43, 0x44};
  EXPECT_EQ(StrFromBytes(bytes), "ABCD");
}

TEST(StrFromBytesTest, DecodeBinaryData) {
  uint8_t bytes[] = {0x00, 0x7f, 0x80, 0xff};
  // Note that we can't use a plain `char*` literal  because \x00 is the C
  // string terminator.
  EXPECT_EQ(StrFromBytes(bytes), std::string("\x00\x7f\x80\xff", 4));
}

TEST(CkStrCopyTest, EqualSizedSrcAndDest) {
  uint8_t bytes[3];
  EXPECT_OK(CryptokiStrCopy("ABC", bytes));
  EXPECT_THAT(bytes, ElementsAre(0x41, 0x42, 0x43));
}

TEST(CkStrCopyTest, WithPadCharacters) {
  uint8_t bytes[4];
  EXPECT_OK(CryptokiStrCopy("AB", bytes));
  EXPECT_THAT(bytes, ElementsAre(0x41, 0x42, 0x20, 0x20));
}

TEST(CkStrCopyTest, OversizedString) {
  uint8_t bytes[2];
  EXPECT_THAT(CryptokiStrCopy("abc", bytes),
              StatusIs(absl::StatusCode::kOutOfRange));
}

TEST(CkStrCopyTest, WithExistingContent) {
  uint8_t bytes[3] = {0x01, 0x02, 0x03};
  EXPECT_OK(CryptokiStrCopy("a", bytes));
  EXPECT_THAT(bytes, ElementsAre('a', ' ', ' '));
}

TEST(CkStrCopyTest, WithAlternatePadChar) {
  uint8_t bytes[4];
  EXPECT_OK(CryptokiStrCopy("ab", bytes, '0'));
  EXPECT_THAT(bytes, ElementsAre('a', 'b', '0', '0'));
}

}  // namespace
}  // namespace kmsp11
