#include "simdutf/lasx/begin.h"
namespace simdutf {
namespace SIMDUTF_IMPLEMENTATION {
namespace {
#ifndef SIMDUTF_LASX_H
  #error "lasx.h must be included"
#endif
using namespace simd;

// convert vmskltz/vmskgez/vmsknz to
// simdutf::tables::utf16_to_utf8::pack_1_2_utf8_bytes index
const uint8_t lasx_1_2_utf8_bytes_mask[] = {
    0,   1,   4,   5,   16,  17,  20,  21,  64,  65,  68,  69,  80,  81,  84,
    85,  2,   3,   6,   7,   18,  19,  22,  23,  66,  67,  70,  71,  82,  83,
    86,  87,  8,   9,   12,  13,  24,  25,  28,  29,  72,  73,  76,  77,  88,
    89,  92,  93,  10,  11,  14,  15,  26,  27,  30,  31,  74,  75,  78,  79,
    90,  91,  94,  95,  32,  33,  36,  37,  48,  49,  52,  53,  96,  97,  100,
    101, 112, 113, 116, 117, 34,  35,  38,  39,  50,  51,  54,  55,  98,  99,
    102, 103, 114, 115, 118, 119, 40,  41,  44,  45,  56,  57,  60,  61,  104,
    105, 108, 109, 120, 121, 124, 125, 42,  43,  46,  47,  58,  59,  62,  63,
    106, 107, 110, 111, 122, 123, 126, 127, 128, 129, 132, 133, 144, 145, 148,
    149, 192, 193, 196, 197, 208, 209, 212, 213, 130, 131, 134, 135, 146, 147,
    150, 151, 194, 195, 198, 199, 210, 211, 214, 215, 136, 137, 140, 141, 152,
    153, 156, 157, 200, 201, 204, 205, 216, 217, 220, 221, 138, 139, 142, 143,
    154, 155, 158, 159, 202, 203, 206, 207, 218, 219, 222, 223, 160, 161, 164,
    165, 176, 177, 180, 181, 224, 225, 228, 229, 240, 241, 244, 245, 162, 163,
    166, 167, 178, 179, 182, 183, 226, 227, 230, 231, 242, 243, 246, 247, 168,
    169, 172, 173, 184, 185, 188, 189, 232, 233, 236, 237, 248, 249, 252, 253,
    170, 171, 174, 175, 186, 187, 190, 191, 234, 235, 238, 239, 250, 251, 254,
    255};

simdutf_really_inline __m128i lsx_swap_bytes(__m128i vec) {
  return __lsx_vshuf4i_b(vec, 0b10110001);
}
simdutf_really_inline __m256i lasx_swap_bytes(__m256i vec) {
  return __lasx_xvshuf4i_b(vec, 0b10110001);
}

simdutf_really_inline bool is_ascii(const simd8x64<uint8_t> &input) {
  return input.is_ascii();
}

simdutf_unused simdutf_really_inline simd8<bool>
must_be_continuation(const simd8<uint8_t> prev1, const simd8<uint8_t> prev2,
                     const simd8<uint8_t> prev3) {
  simd8<bool> is_second_byte = prev1 >= uint8_t(0b11000000u);
  simd8<bool> is_third_byte = prev2 >= uint8_t(0b11100000u);
  simd8<bool> is_fourth_byte = prev3 >= uint8_t(0b11110000u);
  // Use ^ instead of | for is_*_byte, because ^ is commutative, and the caller
  // is using ^ as well. This will work fine because we only have to report
  // errors for cases with 0-1 lead bytes. Multiple lead bytes implies 2
  // overlapping multibyte characters, and if that happens, there is guaranteed
  // to be at least *one* lead byte that is part of only 1 other multibyte
  // character. The error will be detected there.
  return is_second_byte ^ is_third_byte ^ is_fourth_byte;
}

simdutf_really_inline simd8<bool>
must_be_2_3_continuation(const simd8<uint8_t> prev2,
                         const simd8<uint8_t> prev3) {
  simd8<bool> is_third_byte = prev2 >= uint8_t(0b11100000u);
  simd8<bool> is_fourth_byte = prev3 >= uint8_t(0b11110000u);
  return is_third_byte ^ is_fourth_byte;
}

// common functions for utf8 conversions
simdutf_really_inline __m128i convert_utf8_3_byte_to_utf16(__m128i in) {
  // Low half contains  10bbbbbb|10cccccc
  // High half contains 1110aaaa|1110aaaa
  const v16u8 sh = {2, 1, 5, 4, 8, 7, 11, 10, 0, 0, 3, 3, 6, 6, 9, 9};
  const v8u16 v0fff = {0xfff, 0xfff, 0xfff, 0xfff, 0xfff, 0xfff, 0xfff, 0xfff};

  __m128i perm = __lsx_vshuf_b(__lsx_vldi(0), in, (__m128i)sh);
  // 1110aaaa => aaaa0000
  __m128i perm_high = __lsx_vslli_b(__lsx_vbsrl_v(perm, 8), 4);
  // 10bbbbbb 10cccccc => 0010bbbb bbcccccc
  __m128i composed = __lsx_vbitsel_v(__lsx_vsrli_h(perm, 2), /* perm >> 2*/
                                     perm, __lsx_vrepli_h(0x3f) /* 0x003f */);
  // 0010bbbb bbcccccc => aaaabbbb bbcccccc
  composed = __lsx_vbitsel_v(perm_high, composed, (__m128i)v0fff);

  return composed;
}

simdutf_really_inline __m128i convert_utf8_2_byte_to_utf16(__m128i in) {
  // 10bbbbb 110aaaaa => 00bbbbb 000aaaaa
  __m128i composed = __lsx_vand_v(in, __lsx_vldi(0x3f));
  // 00bbbbbb 000aaaaa => 00000aaa aabbbbbb
  composed = __lsx_vbitsel_v(
      __lsx_vsrli_h(__lsx_vslli_h(composed, 8), 2), /* (aaaaa << 8) >> 2 */
      __lsx_vsrli_h(composed, 8),                   /* bbbbbb >> 8 */
      __lsx_vrepli_h(0x3f));                        /* 0x003f */
  return composed;
}

simdutf_really_inline __m128i
convert_utf8_1_to_2_byte_to_utf16(__m128i in, size_t shufutf8_idx) {
  // Converts 6 1-2 byte UTF-8 characters to 6 UTF-16 characters.
  // This is a relatively easy scenario
  // we process SIX (6) input code-code units. The max length in bytes of six
  // code code units spanning between 1 and 2 bytes each is 12 bytes.
  __m128i sh =
      __lsx_vld(reinterpret_cast<const uint8_t *>(
                    simdutf::tables::utf8_to_utf16::shufutf8[shufutf8_idx]),
                0);
  // Shuffle
  // 1 byte: 00000000 0bbbbbbb
  // 2 byte: 110aaaaa 10bbbbbb
  __m128i perm = __lsx_vshuf_b(__lsx_vldi(0), in, sh);
  // 1 byte: 00000000 0bbbbbbb
  // 2 byte: 00000000 00bbbbbb
  __m128i ascii = __lsx_vand_v(perm, __lsx_vrepli_h(0x7f)); // 6 or 7 bits
  // 1 byte: 00000000 00000000
  // 2 byte: 00000aaa aa000000
  __m128i v1f00 = __lsx_vldi(-2785); // -2785(13bit) => 151f
  __m128i composed = __lsx_vsrli_h(__lsx_vand_v(perm, v1f00), 2); // 5 bits
  // Combine with a shift right accumulate
  // 1 byte: 00000000 0bbbbbbb
  // 2 byte: 00000aaa aabbbbbb
  composed = __lsx_vadd_h(ascii, composed);
  return composed;
}

#include "lasx/lasx_validate_utf16.cpp"
#include "lasx/lasx_validate_utf32le.cpp"

#include "lasx/lasx_convert_latin1_to_utf8.cpp"
#include "lasx/lasx_convert_latin1_to_utf16.cpp"
#include "lasx/lasx_convert_latin1_to_utf32.cpp"

#include "lasx/lasx_convert_utf8_to_utf16.cpp"
#include "lasx/lasx_convert_utf8_to_utf32.cpp"
#include "lasx/lasx_convert_utf8_to_latin1.cpp"

#include "lasx/lasx_convert_utf16_to_latin1.cpp"
#include "lasx/lasx_convert_utf16_to_utf8.cpp"
#include "lasx/lasx_convert_utf16_to_utf32.cpp"

#include "lasx/lasx_convert_utf32_to_latin1.cpp"
#include "lasx/lasx_convert_utf32_to_utf8.cpp"
#include "lasx/lasx_convert_utf32_to_utf16.cpp"
#include "lasx/lasx_base64.cpp"

} // namespace
} // namespace SIMDUTF_IMPLEMENTATION
} // namespace simdutf

#include "generic/buf_block_reader.h"
#include "generic/utf8_validation/utf8_lookup4_algorithm.h"
#include "generic/utf8_validation/utf8_validator.h"

// transcoding from UTF-8 to Latin 1
#include "generic/utf8_to_latin1/utf8_to_latin1.h"
#include "generic/utf8_to_latin1/valid_utf8_to_latin1.h"
// transcoding from UTF-8 to UTF-16
#include "generic/utf8_to_utf16/valid_utf8_to_utf16.h"
#include "generic/utf8_to_utf16/utf8_to_utf16.h"
// transcoding from UTF-8 to UTF-32
#include "generic/utf8_to_utf32/valid_utf8_to_utf32.h"
#include "generic/utf8_to_utf32/utf8_to_utf32.h"

#include "scalar/utf32_to_utf16/valid_utf32_to_utf16.h"
#include "scalar/utf32_to_utf16/utf32_to_utf16.h"

// other functions
#include "generic/utf8.h"
#include "generic/utf16.h"
#include "scalar/latin1.h"

//
// Implementation-specific overrides
//
namespace simdutf {
namespace SIMDUTF_IMPLEMENTATION {

simdutf_warn_unused int
implementation::detect_encodings(const char *input,
                                 size_t length) const noexcept {
  // If there is a BOM, then we trust it.
  auto bom_encoding = simdutf::BOM::check_bom(input, length);
  // todo: reimplement as a one-pass algorithm.
  if (bom_encoding != encoding_type::unspecified) {
    return bom_encoding;
  }
  int out = 0;
  if (validate_utf8(input, length)) {
    out |= encoding_type::UTF8;
  }
  if ((length % 2) == 0) {
    if (validate_utf16le(reinterpret_cast<const char16_t *>(input),
                         length / 2)) {
      out |= encoding_type::UTF16_LE;
    }
  }
  if ((length % 4) == 0) {
    if (validate_utf32(reinterpret_cast<const char32_t *>(input), length / 4)) {
      out |= encoding_type::UTF32_LE;
    }
  }
  return out;
}

simdutf_warn_unused bool
implementation::validate_utf8(const char *buf, size_t len) const noexcept {
  return lasx::utf8_validation::generic_validate_utf8(buf, len);
}

simdutf_warn_unused result implementation::validate_utf8_with_errors(
    const char *buf, size_t len) const noexcept {
  return lasx::utf8_validation::generic_validate_utf8_with_errors(buf, len);
}

simdutf_warn_unused bool
implementation::validate_ascii(const char *buf, size_t len) const noexcept {
  return lasx::utf8_validation::generic_validate_ascii(buf, len);
}

simdutf_warn_unused result implementation::validate_ascii_with_errors(
    const char *buf, size_t len) const noexcept {
  return lasx::utf8_validation::generic_validate_ascii_with_errors(buf, len);
}

simdutf_warn_unused bool
implementation::validate_utf16le(const char16_t *buf,
                                 size_t len) const noexcept {
  if (simdutf_unlikely(len == 0)) {
    // empty input is valid. protected the implementation from nullptr.
    return true;
  }
  const char16_t *tail = lasx_validate_utf16<endianness::LITTLE>(buf, len);
  if (tail) {
    return scalar::utf16::validate<endianness::LITTLE>(tail,
                                                       len - (tail - buf));
  } else {
    return false;
  }
}

simdutf_warn_unused bool
implementation::validate_utf16be(const char16_t *buf,
                                 size_t len) const noexcept {
  if (simdutf_unlikely(len == 0)) {
    // empty input is valid. protected the implementation from nullptr.
    return true;
  }
  const char16_t *tail = lasx_validate_utf16<endianness::BIG>(buf, len);
  if (tail) {
    return scalar::utf16::validate<endianness::BIG>(tail, len - (tail - buf));
  } else {
    return false;
  }
}

simdutf_warn_unused result implementation::validate_utf16le_with_errors(
    const char16_t *buf, size_t len) const noexcept {
  if (simdutf_unlikely(len == 0)) {
    return result(error_code::SUCCESS, 0);
  }
  result res = lasx_validate_utf16_with_errors<endianness::LITTLE>(buf, len);
  if (res.count != len) {
    result scalar_res = scalar::utf16::validate_with_errors<endianness::LITTLE>(
        buf + res.count, len - res.count);
    return result(scalar_res.error, res.count + scalar_res.count);
  } else {
    return res;
  }
}

simdutf_warn_unused result implementation::validate_utf16be_with_errors(
    const char16_t *buf, size_t len) const noexcept {
  if (simdutf_unlikely(len == 0)) {
    return result(error_code::SUCCESS, 0);
  }
  result res = lasx_validate_utf16_with_errors<endianness::BIG>(buf, len);
  if (res.count != len) {
    result scalar_res = scalar::utf16::validate_with_errors<endianness::BIG>(
        buf + res.count, len - res.count);
    return result(scalar_res.error, res.count + scalar_res.count);
  } else {
    return res;
  }
}

simdutf_warn_unused bool
implementation::validate_utf32(const char32_t *buf, size_t len) const noexcept {
  if (simdutf_unlikely(len == 0)) {
    // empty input is valid. protected the implementation from nullptr.
    return true;
  }
  const char32_t *tail = lasx_validate_utf32le(buf, len);
  if (tail) {
    return scalar::utf32::validate(tail, len - (tail - buf));
  } else {
    return false;
  }
}

simdutf_warn_unused result implementation::validate_utf32_with_errors(
    const char32_t *buf, size_t len) const noexcept {
  if (simdutf_unlikely(len == 0)) {
    return result(error_code::SUCCESS, 0);
  }
  result res = lasx_validate_utf32le_with_errors(buf, len);
  if (res.count != len) {
    result scalar_res =
        scalar::utf32::validate_with_errors(buf + res.count, len - res.count);
    return result(scalar_res.error, res.count + scalar_res.count);
  } else {
    return res;
  }
}

simdutf_warn_unused size_t implementation::convert_latin1_to_utf8(
    const char *buf, size_t len, char *utf8_output) const noexcept {
  std::pair<const char *, char *> ret =
      lasx_convert_latin1_to_utf8(buf, len, utf8_output);
  size_t converted_chars = ret.second - utf8_output;

  if (ret.first != buf + len) {
    const size_t scalar_converted_chars = scalar::latin1_to_utf8::convert(
        ret.first, len - (ret.first - buf), ret.second);
    converted_chars += scalar_converted_chars;
  }
  return converted_chars;
}

simdutf_warn_unused size_t implementation::convert_latin1_to_utf16le(
    const char *buf, size_t len, char16_t *utf16_output) const noexcept {
  std::pair<const char *, char16_t *> ret =
      lasx_convert_latin1_to_utf16le(buf, len, utf16_output);
  size_t converted_chars = ret.second - utf16_output;
  if (ret.first != buf + len) {
    const size_t scalar_converted_chars =
        scalar::latin1_to_utf16::convert<endianness::LITTLE>(
            ret.first, len - (ret.first - buf), ret.second);
    converted_chars += scalar_converted_chars;
  }
  return converted_chars;
}

simdutf_warn_unused size_t implementation::convert_latin1_to_utf16be(
    const char *buf, size_t len, char16_t *utf16_output) const noexcept {
  std::pair<const char *, char16_t *> ret =
      lasx_convert_latin1_to_utf16be(buf, len, utf16_output);
  size_t converted_chars = ret.second - utf16_output;
  if (ret.first != buf + len) {
    const size_t scalar_converted_chars =
        scalar::latin1_to_utf16::convert<endianness::BIG>(
            ret.first, len - (ret.first - buf), ret.second);
    converted_chars += scalar_converted_chars;
  }
  return converted_chars;
}

simdutf_warn_unused size_t implementation::convert_latin1_to_utf32(
    const char *buf, size_t len, char32_t *utf32_output) const noexcept {
  std::pair<const char *, char32_t *> ret =
      lasx_convert_latin1_to_utf32(buf, len, utf32_output);
  size_t converted_chars = ret.second - utf32_output;
  if (ret.first != buf + len) {
    const size_t scalar_converted_chars = scalar::latin1_to_utf32::convert(
        ret.first, len - (ret.first - buf), ret.second);
    converted_chars += scalar_converted_chars;
  }
  return converted_chars;
}

simdutf_warn_unused size_t implementation::convert_utf8_to_latin1(
    const char *buf, size_t len, char *latin1_output) const noexcept {
  size_t pos = 0;
  char *output_start{latin1_output};
  // Performance degradation when memory address is not 32-byte aligned
  while (((uint64_t)latin1_output & 0x1F) && pos < len) {
    if (buf[pos] & 0x80) {
      if (pos + 1 >= len)
        return 0;
      if ((buf[pos] & 0b11100000) == 0b11000000) {
        if ((buf[pos + 1] & 0b11000000) != 0b10000000)
          return 0;
        uint32_t code_point =
            (buf[pos] & 0b00011111) << 6 | (buf[pos + 1] & 0b00111111);
        if (code_point < 0x80 || 0xFF < code_point) {
          return 0;
        }
        *latin1_output++ = char(code_point);
        pos += 2;
      } else {
        return 0;
      }
    } else {
      *latin1_output++ = char(buf[pos]);
      pos++;
    }
  }
  size_t convert_size = latin1_output - output_start;
  if (pos == len)
    return convert_size;
  utf8_to_latin1::validating_transcoder converter;
  size_t convert_result =
      converter.convert(buf + pos, len - pos, latin1_output);
  return convert_result ? convert_size + convert_result : 0;
}

simdutf_warn_unused result implementation::convert_utf8_to_latin1_with_errors(
    const char *buf, size_t len, char *latin1_output) const noexcept {
  size_t pos = 0;
  char *output_start{latin1_output};
  // Performance degradation when memory address is not 32-byte aligned
  while (((uint64_t)latin1_output & 0x1F) && pos < len) {
    if (buf[pos] & 0x80) {
      if ((buf[pos] & 0b11100000) == 0b11000000) {
        if (pos + 1 >= len)
          return result(error_code::TOO_SHORT, pos);
        if ((buf[pos + 1] & 0b11000000) != 0b10000000)
          return result(error_code::TOO_SHORT, pos);
        uint32_t code_point =
            (buf[pos] & 0b00011111) << 6 | (buf[pos + 1] & 0b00111111);
        if (code_point < 0x80)
          return result(error_code::OVERLONG, pos);
        if (0xFF < code_point)
          return result(error_code::TOO_LARGE, pos);
        *latin1_output++ = char(code_point);
        pos += 2;
      } else if ((buf[pos] & 0b11110000) == 0b11100000) {
        return result(error_code::TOO_LARGE, pos);
      } else if ((buf[pos] & 0b11111000) == 0b11110000) {
        return result(error_code::TOO_LARGE, pos);
      } else {
        if ((buf[pos] & 0b11000000) == 0b10000000) {
          return result(error_code::TOO_LONG, pos);
        }
        return result(error_code::HEADER_BITS, pos);
      }
    } else {
      *latin1_output++ = char(buf[pos]);
      pos++;
    }
  }
  size_t convert_size = latin1_output - output_start;
  if (pos == len)
    return result(error_code::SUCCESS, convert_size);

  utf8_to_latin1::validating_transcoder converter;
  result res =
      converter.convert_with_errors(buf + pos, len - pos, latin1_output);
  return res.error ? result(res.error, res.count + pos)
                   : result(res.error, res.count + convert_size);
}

simdutf_warn_unused size_t implementation::convert_valid_utf8_to_latin1(
    const char *buf, size_t len, char *latin1_output) const noexcept {
  size_t pos = 0;
  char *output_start{latin1_output};
  // Performance degradation when memory address is not 32-byte aligned
  while (((uint64_t)latin1_output & 0x1F) && pos < len) {
    if (buf[pos] & 0x80) {
      if (pos + 1 >= len)
        break;
      if ((buf[pos] & 0b11100000) == 0b11000000) {
        if ((buf[pos + 1] & 0b11000000) != 0b10000000)
          return 0;
        uint32_t code_point =
            (buf[pos] & 0b00011111) << 6 | (buf[pos + 1] & 0b00111111);
        *latin1_output++ = char(code_point);
        pos += 2;
      } else {
        return 0;
      }
    } else {
      *latin1_output++ = char(buf[pos]);
      pos++;
    }
  }
  size_t convert_size = latin1_output - output_start;
  if (pos == len)
    return convert_size;

  size_t convert_result =
      lasx::utf8_to_latin1::convert_valid(buf + pos, len - pos, latin1_output);
  return convert_result ? convert_size + convert_result : 0;
}

simdutf_warn_unused size_t implementation::convert_utf8_to_utf16le(
    const char *buf, size_t len, char16_t *utf16_output) const noexcept {
  utf8_to_utf16::validating_transcoder converter;
  return converter.convert<endianness::LITTLE>(buf, len, utf16_output);
}

simdutf_warn_unused size_t implementation::convert_utf8_to_utf16be(
    const char *buf, size_t len, char16_t *utf16_output) const noexcept {
  utf8_to_utf16::validating_transcoder converter;
  return converter.convert<endianness::BIG>(buf, len, utf16_output);
}

simdutf_warn_unused result implementation::convert_utf8_to_utf16le_with_errors(
    const char *buf, size_t len, char16_t *utf16_output) const noexcept {
  utf8_to_utf16::validating_transcoder converter;
  return converter.convert_with_errors<endianness::LITTLE>(buf, len,
                                                           utf16_output);
}

simdutf_warn_unused result implementation::convert_utf8_to_utf16be_with_errors(
    const char *buf, size_t len, char16_t *utf16_output) const noexcept {
  utf8_to_utf16::validating_transcoder converter;
  return converter.convert_with_errors<endianness::BIG>(buf, len, utf16_output);
}

simdutf_warn_unused size_t implementation::convert_valid_utf8_to_utf16le(
    const char *input, size_t size, char16_t *utf16_output) const noexcept {
  return utf8_to_utf16::convert_valid<endianness::LITTLE>(input, size,
                                                          utf16_output);
}

simdutf_warn_unused size_t implementation::convert_valid_utf8_to_utf16be(
    const char *input, size_t size, char16_t *utf16_output) const noexcept {
  return utf8_to_utf16::convert_valid<endianness::BIG>(input, size,
                                                       utf16_output);
}

simdutf_warn_unused size_t implementation::convert_utf8_to_utf32(
    const char *buf, size_t len, char32_t *utf32_output) const noexcept {
  utf8_to_utf32::validating_transcoder converter;
  return converter.convert(buf, len, utf32_output);
}

simdutf_warn_unused result implementation::convert_utf8_to_utf32_with_errors(
    const char *buf, size_t len, char32_t *utf32_output) const noexcept {
  utf8_to_utf32::validating_transcoder converter;
  return converter.convert_with_errors(buf, len, utf32_output);
}

simdutf_warn_unused size_t implementation::convert_valid_utf8_to_utf32(
    const char *input, size_t size, char32_t *utf32_output) const noexcept {
  return utf8_to_utf32::convert_valid(input, size, utf32_output);
}

simdutf_warn_unused size_t implementation::convert_utf16le_to_latin1(
    const char16_t *buf, size_t len, char *latin1_output) const noexcept {
  std::pair<const char16_t *, char *> ret =
      lasx_convert_utf16_to_latin1<endianness::LITTLE>(buf, len, latin1_output);
  if (ret.first == nullptr) {
    return 0;
  }
  size_t saved_bytes = ret.second - latin1_output;

  if (ret.first != buf + len) {
    const size_t scalar_saved_bytes =
        scalar::utf16_to_latin1::convert<endianness::LITTLE>(
            ret.first, len - (ret.first - buf), ret.second);
    if (scalar_saved_bytes == 0) {
      return 0;
    }
    saved_bytes += scalar_saved_bytes;
  }
  return saved_bytes;
}

simdutf_warn_unused size_t implementation::convert_utf16be_to_latin1(
    const char16_t *buf, size_t len, char *latin1_output) const noexcept {
  std::pair<const char16_t *, char *> ret =
      lasx_convert_utf16_to_latin1<endianness::BIG>(buf, len, latin1_output);
  if (ret.first == nullptr) {
    return 0;
  }
  size_t saved_bytes = ret.second - latin1_output;

  if (ret.first != buf + len) {
    const size_t scalar_saved_bytes =
        scalar::utf16_to_latin1::convert<endianness::BIG>(
            ret.first, len - (ret.first - buf), ret.second);
    if (scalar_saved_bytes == 0) {
      return 0;
    }
    saved_bytes += scalar_saved_bytes;
  }
  return saved_bytes;
}

simdutf_warn_unused result
implementation::convert_utf16le_to_latin1_with_errors(
    const char16_t *buf, size_t len, char *latin1_output) const noexcept {
  std::pair<result, char *> ret =
      lasx_convert_utf16_to_latin1_with_errors<endianness::LITTLE>(
          buf, len, latin1_output);
  if (ret.first.error) {
    return ret.first;
  } // Can return directly since scalar fallback already found correct
    // ret.first.count
  if (ret.first.count != len) { // All good so far, but not finished
    result scalar_res =
        scalar::utf16_to_latin1::convert_with_errors<endianness::LITTLE>(
            buf + ret.first.count, len - ret.first.count, ret.second);
    if (scalar_res.error) {
      scalar_res.count += ret.first.count;
      return scalar_res;
    } else {
      ret.second += scalar_res.count;
    }
  }
  ret.first.count =
      ret.second -
      latin1_output; // Set count to the number of 8-bit code units written
  return ret.first;
}

simdutf_warn_unused result
implementation::convert_utf16be_to_latin1_with_errors(
    const char16_t *buf, size_t len, char *latin1_output) const noexcept {
  std::pair<result, char *> ret =
      lasx_convert_utf16_to_latin1_with_errors<endianness::BIG>(buf, len,
                                                                latin1_output);
  if (ret.first.error) {
    return ret.first;
  } // Can return directly since scalar fallback already found correct
    // ret.first.count
  if (ret.first.count != len) { // All good so far, but not finished
    result scalar_res =
        scalar::utf16_to_latin1::convert_with_errors<endianness::BIG>(
            buf + ret.first.count, len - ret.first.count, ret.second);
    if (scalar_res.error) {
      scalar_res.count += ret.first.count;
      return scalar_res;
    } else {
      ret.second += scalar_res.count;
    }
  }
  ret.first.count =
      ret.second -
      latin1_output; // Set count to the number of 8-bit code units written
  return ret.first;
}

simdutf_warn_unused size_t implementation::convert_valid_utf16be_to_latin1(
    const char16_t *buf, size_t len, char *latin1_output) const noexcept {
  // optimization opportunity: implement a custom function.
  return convert_utf16be_to_latin1(buf, len, latin1_output);
}

simdutf_warn_unused size_t implementation::convert_valid_utf16le_to_latin1(
    const char16_t *buf, size_t len, char *latin1_output) const noexcept {
  // optimization opportunity: implement a custom function.
  return convert_utf16le_to_latin1(buf, len, latin1_output);
}

simdutf_warn_unused size_t implementation::convert_utf16le_to_utf8(
    const char16_t *buf, size_t len, char *utf8_output) const noexcept {
  std::pair<const char16_t *, char *> ret =
      lasx_convert_utf16_to_utf8<endianness::LITTLE>(buf, len, utf8_output);
  if (ret.first == nullptr) {
    return 0;
  }
  size_t saved_bytes = ret.second - utf8_output;
  if (ret.first != buf + len) {
    const size_t scalar_saved_bytes =
        scalar::utf16_to_utf8::convert<endianness::LITTLE>(
            ret.first, len - (ret.first - buf), ret.second);
    if (scalar_saved_bytes == 0) {
      return 0;
    }
    saved_bytes += scalar_saved_bytes;
  }
  return saved_bytes;
}

simdutf_warn_unused size_t implementation::convert_utf16be_to_utf8(
    const char16_t *buf, size_t len, char *utf8_output) const noexcept {
  std::pair<const char16_t *, char *> ret =
      lasx_convert_utf16_to_utf8<endianness::BIG>(buf, len, utf8_output);
  if (ret.first == nullptr) {
    return 0;
  }
  size_t saved_bytes = ret.second - utf8_output;
  if (ret.first != buf + len) {
    const size_t scalar_saved_bytes =
        scalar::utf16_to_utf8::convert<endianness::BIG>(
            ret.first, len - (ret.first - buf), ret.second);
    if (scalar_saved_bytes == 0) {
      return 0;
    }
    saved_bytes += scalar_saved_bytes;
  }
  return saved_bytes;
}

simdutf_warn_unused result implementation::convert_utf16le_to_utf8_with_errors(
    const char16_t *buf, size_t len, char *utf8_output) const noexcept {
  // ret.first.count is always the position in the buffer, not the number of
  // code units written even if finished
  std::pair<result, char *> ret =
      lasx_convert_utf16_to_utf8_with_errors<endianness::LITTLE>(buf, len,
                                                                 utf8_output);
  if (ret.first.error) {
    return ret.first;
  } // Can return directly since scalar fallback already found correct
    // ret.first.count
  if (ret.first.count != len) { // All good so far, but not finished
    result scalar_res =
        scalar::utf16_to_utf8::convert_with_errors<endianness::LITTLE>(
            buf + ret.first.count, len - ret.first.count, ret.second);
    if (scalar_res.error) {
      scalar_res.count += ret.first.count;
      return scalar_res;
    } else {
      ret.second += scalar_res.count;
    }
  }
  ret.first.count =
      ret.second -
      utf8_output; // Set count to the number of 8-bit code units written
  return ret.first;
}

simdutf_warn_unused result implementation::convert_utf16be_to_utf8_with_errors(
    const char16_t *buf, size_t len, char *utf8_output) const noexcept {
  // ret.first.count is always the position in the buffer, not the number of
  // code units written even if finished
  std::pair<result, char *> ret =
      lasx_convert_utf16_to_utf8_with_errors<endianness::BIG>(buf, len,
                                                              utf8_output);
  if (ret.first.error) {
    return ret.first;
  } // Can return directly since scalar fallback already found correct
    // ret.first.count
  if (ret.first.count != len) { // All good so far, but not finished
    result scalar_res =
        scalar::utf16_to_utf8::convert_with_errors<endianness::BIG>(
            buf + ret.first.count, len - ret.first.count, ret.second);
    if (scalar_res.error) {
      scalar_res.count += ret.first.count;
      return scalar_res;
    } else {
      ret.second += scalar_res.count;
    }
  }
  ret.first.count =
      ret.second -
      utf8_output; // Set count to the number of 8-bit code units written
  return ret.first;
}

simdutf_warn_unused size_t implementation::convert_valid_utf16le_to_utf8(
    const char16_t *buf, size_t len, char *utf8_output) const noexcept {
  return convert_utf16le_to_utf8(buf, len, utf8_output);
}

simdutf_warn_unused size_t implementation::convert_valid_utf16be_to_utf8(
    const char16_t *buf, size_t len, char *utf8_output) const noexcept {
  return convert_utf16be_to_utf8(buf, len, utf8_output);
}

simdutf_warn_unused size_t implementation::convert_utf32_to_utf8(
    const char32_t *buf, size_t len, char *utf8_output) const noexcept {
  if (simdutf_unlikely(len == 0)) {
    return 0;
  }
  std::pair<const char32_t *, char *> ret =
      lasx_convert_utf32_to_utf8(buf, len, utf8_output);
  if (ret.first == nullptr) {
    return 0;
  }
  size_t saved_bytes = ret.second - utf8_output;
  if (ret.first != buf + len) {
    const size_t scalar_saved_bytes = scalar::utf32_to_utf8::convert(
        ret.first, len - (ret.first - buf), ret.second);
    if (scalar_saved_bytes == 0) {
      return 0;
    }
    saved_bytes += scalar_saved_bytes;
  }
  return saved_bytes;
}

simdutf_warn_unused result implementation::convert_utf32_to_utf8_with_errors(
    const char32_t *buf, size_t len, char *utf8_output) const noexcept {
  if (simdutf_unlikely(len == 0)) {
    return result(error_code::SUCCESS, 0);
  }
  // ret.first.count is always the position in the buffer, not the number of
  // code units written even if finished
  std::pair<result, char *> ret =
      lasx_convert_utf32_to_utf8_with_errors(buf, len, utf8_output);
  if (ret.first.count != len) {
    result scalar_res = scalar::utf32_to_utf8::convert_with_errors(
        buf + ret.first.count, len - ret.first.count, ret.second);
    if (scalar_res.error) {
      scalar_res.count += ret.first.count;
      return scalar_res;
    } else {
      ret.second += scalar_res.count;
    }
  }
  ret.first.count =
      ret.second -
      utf8_output; // Set count to the number of 8-bit code units written
  return ret.first;
}

simdutf_warn_unused size_t implementation::convert_utf16le_to_utf32(
    const char16_t *buf, size_t len, char32_t *utf32_output) const noexcept {
  std::pair<const char16_t *, char32_t *> ret =
      lasx_convert_utf16_to_utf32<endianness::LITTLE>(buf, len, utf32_output);
  if (ret.first == nullptr) {
    return 0;
  }
  size_t saved_bytes = ret.second - utf32_output;
  if (ret.first != buf + len) {
    const size_t scalar_saved_bytes =
        scalar::utf16_to_utf32::convert<endianness::LITTLE>(
            ret.first, len - (ret.first - buf), ret.second);
    if (scalar_saved_bytes == 0) {
      return 0;
    }
    saved_bytes += scalar_saved_bytes;
  }
  return saved_bytes;
}

simdutf_warn_unused size_t implementation::convert_utf16be_to_utf32(
    const char16_t *buf, size_t len, char32_t *utf32_output) const noexcept {
  std::pair<const char16_t *, char32_t *> ret =
      lasx_convert_utf16_to_utf32<endianness::BIG>(buf, len, utf32_output);
  if (ret.first == nullptr) {
    return 0;
  }
  size_t saved_bytes = ret.second - utf32_output;
  if (ret.first != buf + len) {
    const size_t scalar_saved_bytes =
        scalar::utf16_to_utf32::convert<endianness::BIG>(
            ret.first, len - (ret.first - buf), ret.second);
    if (scalar_saved_bytes == 0) {
      return 0;
    }
    saved_bytes += scalar_saved_bytes;
  }
  return saved_bytes;
}

simdutf_warn_unused result implementation::convert_utf16le_to_utf32_with_errors(
    const char16_t *buf, size_t len, char32_t *utf32_output) const noexcept {
  // ret.first.count is always the position in the buffer, not the number of
  // code units written even if finished
  std::pair<result, char32_t *> ret =
      lasx_convert_utf16_to_utf32_with_errors<endianness::LITTLE>(buf, len,
                                                                  utf32_output);
  if (ret.first.error) {
    return ret.first;
  } // Can return directly since scalar fallback already found correct
    // ret.first.count
  if (ret.first.count != len) { // All good so far, but not finished
    result scalar_res =
        scalar::utf16_to_utf32::convert_with_errors<endianness::LITTLE>(
            buf + ret.first.count, len - ret.first.count, ret.second);
    if (scalar_res.error) {
      scalar_res.count += ret.first.count;
      return scalar_res;
    } else {
      ret.second += scalar_res.count;
    }
  }
  ret.first.count =
      ret.second -
      utf32_output; // Set count to the number of 8-bit code units written
  return ret.first;
}

simdutf_warn_unused result implementation::convert_utf16be_to_utf32_with_errors(
    const char16_t *buf, size_t len, char32_t *utf32_output) const noexcept {
  // ret.first.count is always the position in the buffer, not the number of
  // code units written even if finished
  std::pair<result, char32_t *> ret =
      lasx_convert_utf16_to_utf32_with_errors<endianness::BIG>(buf, len,
                                                               utf32_output);
  if (ret.first.error) {
    return ret.first;
  } // Can return directly since scalar fallback already found correct
    // ret.first.count
  if (ret.first.count != len) { // All good so far, but not finished
    result scalar_res =
        scalar::utf16_to_utf32::convert_with_errors<endianness::BIG>(
            buf + ret.first.count, len - ret.first.count, ret.second);
    if (scalar_res.error) {
      scalar_res.count += ret.first.count;
      return scalar_res;
    } else {
      ret.second += scalar_res.count;
    }
  }
  ret.first.count =
      ret.second -
      utf32_output; // Set count to the number of 8-bit code units written
  return ret.first;
}

simdutf_warn_unused size_t implementation::convert_utf32_to_latin1(
    const char32_t *buf, size_t len, char *latin1_output) const noexcept {
  std::pair<const char32_t *, char *> ret =
      lasx_convert_utf32_to_latin1(buf, len, latin1_output);
  if (ret.first == nullptr) {
    return 0;
  }
  size_t saved_bytes = ret.second - latin1_output;

  if (ret.first != buf + len) {
    const size_t scalar_saved_bytes = scalar::utf32_to_latin1::convert(
        ret.first, len - (ret.first - buf), ret.second);
    if (scalar_saved_bytes == 0) {
      return 0;
    }
    saved_bytes += scalar_saved_bytes;
  }
  return saved_bytes;
}

simdutf_warn_unused result implementation::convert_utf32_to_latin1_with_errors(
    const char32_t *buf, size_t len, char *latin1_output) const noexcept {
  std::pair<result, char *> ret =
      lasx_convert_utf32_to_latin1_with_errors(buf, len, latin1_output);
  if (ret.first.error) {
    return ret.first;
  } // Can return directly since scalar fallback already found correct
    // ret.first.count
  if (ret.first.count != len) { // All good so far, but not finished
    result scalar_res = scalar::utf32_to_latin1::convert_with_errors(
        buf + ret.first.count, len - ret.first.count, ret.second);
    if (scalar_res.error) {
      scalar_res.count += ret.first.count;
      return scalar_res;
    } else {
      ret.second += scalar_res.count;
    }
  }
  ret.first.count =
      ret.second -
      latin1_output; // Set count to the number of 8-bit code units written
  return ret.first;
}

simdutf_warn_unused size_t implementation::convert_valid_utf32_to_latin1(
    const char32_t *buf, size_t len, char *latin1_output) const noexcept {
  std::pair<const char32_t *, char *> ret =
      lasx_convert_utf32_to_latin1(buf, len, latin1_output);
  if (ret.first == nullptr) {
    return 0;
  }
  size_t saved_bytes = ret.second - latin1_output;

  if (ret.first != buf + len) {
    const size_t scalar_saved_bytes = scalar::utf32_to_latin1::convert_valid(
        ret.first, len - (ret.first - buf), ret.second);
    saved_bytes += scalar_saved_bytes;
  }
  return saved_bytes;
}

simdutf_warn_unused size_t implementation::convert_valid_utf32_to_utf8(
    const char32_t *buf, size_t len, char *utf8_output) const noexcept {
  // optimization opportunity: implement a custom function.
  return convert_utf32_to_utf8(buf, len, utf8_output);
}

simdutf_warn_unused size_t implementation::convert_utf32_to_utf16le(
    const char32_t *buf, size_t len, char16_t *utf16_output) const noexcept {
  std::pair<const char32_t *, char16_t *> ret =
      lasx_convert_utf32_to_utf16<endianness::LITTLE>(buf, len, utf16_output);
  if (ret.first == nullptr) {
    return 0;
  }
  size_t saved_bytes = ret.second - utf16_output;
  if (ret.first != buf + len) {
    const size_t scalar_saved_bytes =
        scalar::utf32_to_utf16::convert<endianness::LITTLE>(
            ret.first, len - (ret.first - buf), ret.second);
    if (scalar_saved_bytes == 0) {
      return 0;
    }
    saved_bytes += scalar_saved_bytes;
  }

  return saved_bytes;
}

simdutf_warn_unused size_t implementation::convert_utf32_to_utf16be(
    const char32_t *buf, size_t len, char16_t *utf16_output) const noexcept {
  std::pair<const char32_t *, char16_t *> ret =
      lasx_convert_utf32_to_utf16<endianness::BIG>(buf, len, utf16_output);
  if (ret.first == nullptr) {
    return 0;
  }
  size_t saved_bytes = ret.second - utf16_output;
  if (ret.first != buf + len) {
    const size_t scalar_saved_bytes =
        scalar::utf32_to_utf16::convert<endianness::BIG>(
            ret.first, len - (ret.first - buf), ret.second);
    if (scalar_saved_bytes == 0) {
      return 0;
    }
    saved_bytes += scalar_saved_bytes;
  }
  return saved_bytes;
}

simdutf_warn_unused result implementation::convert_utf32_to_utf16le_with_errors(
    const char32_t *buf, size_t len, char16_t *utf16_output) const noexcept {
  // ret.first.count is always the position in the buffer, not the number of
  // code units written even if finished
  std::pair<result, char16_t *> ret =
      lasx_convert_utf32_to_utf16_with_errors<endianness::LITTLE>(buf, len,
                                                                  utf16_output);
  if (ret.first.count != len) {
    result scalar_res =
        scalar::utf32_to_utf16::convert_with_errors<endianness::LITTLE>(
            buf + ret.first.count, len - ret.first.count, ret.second);
    if (scalar_res.error) {
      scalar_res.count += ret.first.count;
      return scalar_res;
    } else {
      ret.second += scalar_res.count;
    }
  }
  ret.first.count =
      ret.second -
      utf16_output; // Set count to the number of 8-bit code units written
  return ret.first;
}

simdutf_warn_unused result implementation::convert_utf32_to_utf16be_with_errors(
    const char32_t *buf, size_t len, char16_t *utf16_output) const noexcept {
  // ret.first.count is always the position in the buffer, not the number of
  // code units written even if finished
  std::pair<result, char16_t *> ret =
      lasx_convert_utf32_to_utf16_with_errors<endianness::BIG>(buf, len,
                                                               utf16_output);
  if (ret.first.count != len) {
    result scalar_res =
        scalar::utf32_to_utf16::convert_with_errors<endianness::BIG>(
            buf + ret.first.count, len - ret.first.count, ret.second);
    if (scalar_res.error) {
      scalar_res.count += ret.first.count;
      return scalar_res;
    } else {
      ret.second += scalar_res.count;
    }
  }
  ret.first.count =
      ret.second -
      utf16_output; // Set count to the number of 8-bit code units written
  return ret.first;
}

simdutf_warn_unused size_t implementation::convert_valid_utf32_to_utf16le(
    const char32_t *buf, size_t len, char16_t *utf16_output) const noexcept {
  return convert_utf32_to_utf16le(buf, len, utf16_output);
}

simdutf_warn_unused size_t implementation::convert_valid_utf32_to_utf16be(
    const char32_t *buf, size_t len, char16_t *utf16_output) const noexcept {
  return convert_utf32_to_utf16be(buf, len, utf16_output);
}

simdutf_warn_unused size_t implementation::convert_valid_utf16le_to_utf32(
    const char16_t *buf, size_t len, char32_t *utf32_output) const noexcept {
  return convert_utf16le_to_utf32(buf, len, utf32_output);
}

simdutf_warn_unused size_t implementation::convert_valid_utf16be_to_utf32(
    const char16_t *buf, size_t len, char32_t *utf32_output) const noexcept {
  return convert_utf16be_to_utf32(buf, len, utf32_output);
}

void implementation::change_endianness_utf16(const char16_t *input,
                                             size_t length,
                                             char16_t *output) const noexcept {
  utf16::change_endianness_utf16(input, length, output);
}

simdutf_warn_unused size_t implementation::count_utf16le(
    const char16_t *input, size_t length) const noexcept {
  return utf16::count_code_points<endianness::LITTLE>(input, length);
}

simdutf_warn_unused size_t implementation::count_utf16be(
    const char16_t *input, size_t length) const noexcept {
  return utf16::count_code_points<endianness::BIG>(input, length);
}

simdutf_warn_unused size_t
implementation::count_utf8(const char *input, size_t length) const noexcept {
  size_t pos = 0;
  size_t count = 0;
  // Performance degradation when memory address is not 32-byte aligned
  while ((((uint64_t)input + pos) & 0x1F && pos < length)) {
    if (input[pos++] > -65) {
      count++;
    }
  }
  __m256i v_bf = __lasx_xvldi(0xBF); // 0b10111111
  for (; pos + 32 <= length; pos += 32) {
    __m256i in = __lasx_xvld(reinterpret_cast<const int8_t *>(input + pos), 0);
    __m256i utf8_count =
        __lasx_xvpcnt_h(__lasx_xvmskltz_b(__lasx_xvslt_b(v_bf, in)));
    count = count + __lasx_xvpickve2gr_wu(utf8_count, 0) +
            __lasx_xvpickve2gr_wu(utf8_count, 4);
  }
  return count + scalar::utf8::count_code_points(input + pos, length - pos);
}

simdutf_warn_unused size_t implementation::latin1_length_from_utf8(
    const char *buf, size_t len) const noexcept {
  return count_utf8(buf, len);
}

simdutf_warn_unused size_t
implementation::latin1_length_from_utf16(size_t length) const noexcept {
  return length;
}

simdutf_warn_unused size_t
implementation::latin1_length_from_utf32(size_t length) const noexcept {
  return length;
}

simdutf_warn_unused size_t implementation::utf8_length_from_latin1(
    const char *input, size_t length) const noexcept {
  const uint8_t *data = reinterpret_cast<const uint8_t *>(input);
  const uint8_t *data_end = data + length;
  uint64_t result = 0;
  while (data + 16 < data_end) {
    uint64_t two_bytes = 0;
    __m128i input_vec = __lsx_vld(data, 0);
    two_bytes =
        __lsx_vpickve2gr_hu(__lsx_vpcnt_h(__lsx_vmskltz_b(input_vec)), 0);
    result += 16 + two_bytes;
    data += 16;
  }
  return result + scalar::latin1::utf8_length_from_latin1((const char *)data,
                                                          data_end - data);
}

simdutf_warn_unused size_t implementation::utf8_length_from_utf16le(
    const char16_t *input, size_t length) const noexcept {
  return utf16::utf8_length_from_utf16<endianness::LITTLE>(input, length);
}

simdutf_warn_unused size_t implementation::utf8_length_from_utf16be(
    const char16_t *input, size_t length) const noexcept {
  return utf16::utf8_length_from_utf16<endianness::BIG>(input, length);
}

simdutf_warn_unused size_t
implementation::utf16_length_from_latin1(size_t length) const noexcept {
  return length;
}

simdutf_warn_unused size_t
implementation::utf32_length_from_latin1(size_t length) const noexcept {
  return length;
}

simdutf_warn_unused size_t implementation::utf32_length_from_utf16le(
    const char16_t *input, size_t length) const noexcept {
  return utf16::utf32_length_from_utf16<endianness::LITTLE>(input, length);
}

simdutf_warn_unused size_t implementation::utf32_length_from_utf16be(
    const char16_t *input, size_t length) const noexcept {
  return utf16::utf32_length_from_utf16<endianness::BIG>(input, length);
}

simdutf_warn_unused size_t implementation::utf16_length_from_utf8(
    const char *input, size_t length) const noexcept {
  return utf8::utf16_length_from_utf8(input, length);
}

simdutf_warn_unused size_t implementation::utf8_length_from_utf32(
    const char32_t *input, size_t length) const noexcept {
  __m256i v_80 = __lasx_xvrepli_w(0x80); /*0x00000080*/
  __m256i v_800 = __lasx_xvldi(-3832);   /*0x00000800*/
  __m256i v_10000 = __lasx_xvldi(-3583); /*0x00010000*/
  size_t pos = 0;
  size_t count = 0;
  for (; pos + 8 <= length; pos += 8) {
    __m256i in =
        __lasx_xvld(reinterpret_cast<const uint32_t *>(input + pos), 0);
    __m256i ascii_bytes_bytemask = __lasx_xvslt_w(in, v_80);
    __m256i one_two_bytes_bytemask = __lasx_xvslt_w(in, v_800);
    __m256i two_bytes_bytemask =
        __lasx_xvxor_v(one_two_bytes_bytemask, ascii_bytes_bytemask);
    __m256i three_bytes_bytemask =
        __lasx_xvxor_v(__lasx_xvslt_w(in, v_10000), one_two_bytes_bytemask);

    __m256i ascii_bytes =
        __lasx_xvpcnt_w(__lasx_xvmskltz_w(ascii_bytes_bytemask));
    const uint32_t ascii_bytes_count = __lasx_xvpickve2gr_wu(ascii_bytes, 0) +
                                       __lasx_xvpickve2gr_wu(ascii_bytes, 4);
    __m256i two_bytes = __lasx_xvpcnt_w(__lasx_xvmskltz_w(two_bytes_bytemask));
    const uint32_t two_bytes_count = __lasx_xvpickve2gr_wu(two_bytes, 0) +
                                     __lasx_xvpickve2gr_wu(two_bytes, 4);
    __m256i three_bytes =
        __lasx_xvpcnt_w(__lasx_xvmskltz_w(three_bytes_bytemask));
    const uint32_t three_bytes_count = __lasx_xvpickve2gr_wu(three_bytes, 0) +
                                       __lasx_xvpickve2gr_wu(three_bytes, 4);

    count +=
        32 - 3 * ascii_bytes_count - 2 * two_bytes_count - three_bytes_count;
  }
  return count +
         scalar::utf32::utf8_length_from_utf32(input + pos, length - pos);
}

simdutf_warn_unused size_t implementation::utf16_length_from_utf32(
    const char32_t *input, size_t length) const noexcept {
  __m128i v_ffff = __lsx_vldi(-2304); /*0x0000ffff*/
  size_t pos = 0;
  size_t count = 0;
  for (; pos + 4 <= length; pos += 4) {
    __m128i in = __lsx_vld(reinterpret_cast<const uint32_t *>(input + pos), 0);
    __m128i surrogate_bytemask = __lsx_vslt_wu(v_ffff, in);
    size_t surrogate_count = __lsx_vpickve2gr_bu(
        __lsx_vpcnt_b(__lsx_vmskltz_w(surrogate_bytemask)), 0);
    count += 4 + surrogate_count;
  }
  return count +
         scalar::utf32::utf16_length_from_utf32(input + pos, length - pos);
}

simdutf_warn_unused size_t implementation::utf32_length_from_utf8(
    const char *input, size_t length) const noexcept {
  return utf8::count_code_points(input, length);
}

simdutf_warn_unused size_t implementation::maximal_binary_length_from_base64(
    const char *input, size_t length) const noexcept {
  return scalar::base64::maximal_binary_length_from_base64(input, length);
}

simdutf_warn_unused result implementation::base64_to_binary(
    const char *input, size_t length, char *output, base64_options options,
    last_chunk_handling_options last_chunk_options) const noexcept {
  return (options & base64_url)
             ? compress_decode_base64<true>(output, input, length, options,
                                            last_chunk_options)
             : compress_decode_base64<false>(output, input, length, options,
                                             last_chunk_options);
}

simdutf_warn_unused full_result implementation::base64_to_binary_details(
    const char *input, size_t length, char *output, base64_options options,
    last_chunk_handling_options last_chunk_options) const noexcept {
  return (options & base64_url)
             ? compress_decode_base64<true>(output, input, length, options,
                                            last_chunk_options)
             : compress_decode_base64<false>(output, input, length, options,
                                             last_chunk_options);
}

simdutf_warn_unused size_t implementation::maximal_binary_length_from_base64(
    const char16_t *input, size_t length) const noexcept {
  return scalar::base64::maximal_binary_length_from_base64(input, length);
}

simdutf_warn_unused result implementation::base64_to_binary(
    const char16_t *input, size_t length, char *output, base64_options options,
    last_chunk_handling_options last_chunk_options) const noexcept {
  return (options & base64_url)
             ? compress_decode_base64<true>(output, input, length, options,
                                            last_chunk_options)
             : compress_decode_base64<false>(output, input, length, options,
                                             last_chunk_options);
}

simdutf_warn_unused full_result implementation::base64_to_binary_details(
    const char16_t *input, size_t length, char *output, base64_options options,
    last_chunk_handling_options last_chunk_options) const noexcept {
  return (options & base64_url)
             ? compress_decode_base64<true>(output, input, length, options,
                                            last_chunk_options)
             : compress_decode_base64<false>(output, input, length, options,
                                             last_chunk_options);
}

simdutf_warn_unused size_t implementation::base64_length_from_binary(
    size_t length, base64_options options) const noexcept {
  return scalar::base64::base64_length_from_binary(length, options);
}

size_t implementation::binary_to_base64(const char *input, size_t length,
                                        char *output,
                                        base64_options options) const noexcept {
  if (options & base64_url) {
    return encode_base64<true>(output, input, length, options);
  } else {
    return encode_base64<false>(output, input, length, options);
  }
}
} // namespace SIMDUTF_IMPLEMENTATION
} // namespace simdutf

#include "simdutf/lasx/end.h"
