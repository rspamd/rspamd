#ifndef SIMDUTF_VALID_UTF8_TO_UTF16_H
#define SIMDUTF_VALID_UTF8_TO_UTF16_H

namespace simdutf {
namespace scalar {
namespace {
namespace utf8_to_utf16 {

template <endianness big_endian>
inline size_t convert_valid(const char *buf, size_t len,
                            char16_t *utf16_output) {
  const uint8_t *data = reinterpret_cast<const uint8_t *>(buf);
  size_t pos = 0;
  char16_t *start{utf16_output};
  while (pos < len) {
    // try to convert the next block of 8 ASCII bytes
    if (pos + 8 <=
        len) { // if it is safe to read 8 more bytes, check that they are ascii
      uint64_t v;
      ::memcpy(&v, data + pos, sizeof(uint64_t));
      if ((v & 0x8080808080808080) == 0) {
        size_t final_pos = pos + 8;
        while (pos < final_pos) {
          *utf16_output++ = !match_system(big_endian)
                                ? char16_t(utf16::swap_bytes(buf[pos]))
                                : char16_t(buf[pos]);
          pos++;
        }
        continue;
      }
    }
    uint8_t leading_byte = data[pos]; // leading byte
    if (leading_byte < 0b10000000) {
      // converting one ASCII byte !!!
      *utf16_output++ = !match_system(big_endian)
                            ? char16_t(utf16::swap_bytes(leading_byte))
                            : char16_t(leading_byte);
      pos++;
    } else if ((leading_byte & 0b11100000) == 0b11000000) {
      // We have a two-byte UTF-8, it should become
      // a single UTF-16 word.
      if (pos + 1 >= len) {
        break;
      } // minimal bound checking
      uint16_t code_point = uint16_t(((leading_byte & 0b00011111) << 6) |
                                     (data[pos + 1] & 0b00111111));
      if (!match_system(big_endian)) {
        code_point = utf16::swap_bytes(uint16_t(code_point));
      }
      *utf16_output++ = char16_t(code_point);
      pos += 2;
    } else if ((leading_byte & 0b11110000) == 0b11100000) {
      // We have a three-byte UTF-8, it should become
      // a single UTF-16 word.
      if (pos + 2 >= len) {
        break;
      } // minimal bound checking
      uint16_t code_point = uint16_t(((leading_byte & 0b00001111) << 12) |
                                     ((data[pos + 1] & 0b00111111) << 6) |
                                     (data[pos + 2] & 0b00111111));
      if (!match_system(big_endian)) {
        code_point = utf16::swap_bytes(uint16_t(code_point));
      }
      *utf16_output++ = char16_t(code_point);
      pos += 3;
    } else if ((leading_byte & 0b11111000) == 0b11110000) { // 0b11110000
      // we have a 4-byte UTF-8 word.
      if (pos + 3 >= len) {
        break;
      } // minimal bound checking
      uint32_t code_point = ((leading_byte & 0b00000111) << 18) |
                            ((data[pos + 1] & 0b00111111) << 12) |
                            ((data[pos + 2] & 0b00111111) << 6) |
                            (data[pos + 3] & 0b00111111);
      code_point -= 0x10000;
      uint16_t high_surrogate = uint16_t(0xD800 + (code_point >> 10));
      uint16_t low_surrogate = uint16_t(0xDC00 + (code_point & 0x3FF));
      if (!match_system(big_endian)) {
        high_surrogate = utf16::swap_bytes(high_surrogate);
        low_surrogate = utf16::swap_bytes(low_surrogate);
      }
      *utf16_output++ = char16_t(high_surrogate);
      *utf16_output++ = char16_t(low_surrogate);
      pos += 4;
    } else {
      // we may have a continuation but we do not do error checking
      return 0;
    }
  }
  return utf16_output - start;
}

} // namespace utf8_to_utf16
} // unnamed namespace
} // namespace scalar
} // namespace simdutf

#endif
