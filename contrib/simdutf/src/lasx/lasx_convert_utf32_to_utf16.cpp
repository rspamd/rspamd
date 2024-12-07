template <endianness big_endian>
std::pair<const char32_t *, char16_t *>
lasx_convert_utf32_to_utf16(const char32_t *buf, size_t len,
                            char16_t *utf16_out) {
  uint16_t *utf16_output = reinterpret_cast<uint16_t *>(utf16_out);
  const char32_t *end = buf + len;

  // Performance degradation when memory address is not 32-byte aligned
  while (((uint64_t)utf16_output & 0x1F) && buf < end) {
    uint32_t word = *buf++;
    if ((word & 0xFFFF0000) == 0) {
      // will not generate a surrogate pair
      if (word >= 0xD800 && word <= 0xDFFF) {
        return std::make_pair(nullptr,
                              reinterpret_cast<char16_t *>(utf16_output));
      }
      *utf16_output++ = !match_system(big_endian)
                            ? char16_t(word >> 8 | word << 8)
                            : char16_t(word);
      // buf++;
    } else {
      // will generate a surrogate pair
      if (word > 0x10FFFF) {
        return std::make_pair(nullptr,
                              reinterpret_cast<char16_t *>(utf16_output));
      }
      word -= 0x10000;
      uint16_t high_surrogate = uint16_t(0xD800 + (word >> 10));
      uint16_t low_surrogate = uint16_t(0xDC00 + (word & 0x3FF));
      if (!match_system(big_endian)) {
        high_surrogate = uint16_t(high_surrogate >> 8 | high_surrogate << 8);
        low_surrogate = uint16_t(low_surrogate << 8 | low_surrogate >> 8);
      }
      *utf16_output++ = char16_t(high_surrogate);
      *utf16_output++ = char16_t(low_surrogate);
      // buf++;
    }
  }

  __m256i forbidden_bytemask = __lasx_xvrepli_h(0);
  __m256i v_d800 = __lasx_xvldi(-2600); /*0xD800*/
  __m256i v_dfff = __lasx_xvreplgr2vr_h(uint16_t(0xdfff));
  while (buf + 16 <= end) {
    __m256i in0 = __lasx_xvld(reinterpret_cast<const uint32_t *>(buf), 0);
    __m256i in1 = __lasx_xvld(reinterpret_cast<const uint32_t *>(buf), 32);

    // Check if no bits set above 16th
    if (__lasx_xbz_v(__lasx_xvpickod_h(in1, in0))) {
      __m256i utf16_packed =
          __lasx_xvpermi_d(__lasx_xvpickev_h(in1, in0), 0b11011000);
      forbidden_bytemask = __lasx_xvor_v(
          __lasx_xvand_v(
              __lasx_xvsle_h(utf16_packed, v_dfff),  // utf16_packed <= 0xdfff
              __lasx_xvsle_h(v_d800, utf16_packed)), // utf16_packed >= 0xd800
          forbidden_bytemask);

      if (!match_system(big_endian)) {
        utf16_packed = lasx_swap_bytes(utf16_packed);
      }
      __lasx_xvst(utf16_packed, utf16_output, 0);
      utf16_output += 16;
      buf += 16;
    } else {
      size_t forward = 15;
      size_t k = 0;
      if (size_t(end - buf) < forward + 1) {
        forward = size_t(end - buf - 1);
      }
      for (; k < forward; k++) {
        uint32_t word = buf[k];
        if ((word & 0xFFFF0000) == 0) {
          // will not generate a surrogate pair
          if (word >= 0xD800 && word <= 0xDFFF) {
            return std::make_pair(nullptr,
                                  reinterpret_cast<char16_t *>(utf16_output));
          }
          *utf16_output++ = !match_system(big_endian)
                                ? char16_t(word >> 8 | word << 8)
                                : char16_t(word);
        } else {
          // will generate a surrogate pair
          if (word > 0x10FFFF) {
            return std::make_pair(nullptr,
                                  reinterpret_cast<char16_t *>(utf16_output));
          }
          word -= 0x10000;
          uint16_t high_surrogate = uint16_t(0xD800 + (word >> 10));
          uint16_t low_surrogate = uint16_t(0xDC00 + (word & 0x3FF));
          if (!match_system(big_endian)) {
            high_surrogate =
                uint16_t(high_surrogate >> 8 | high_surrogate << 8);
            low_surrogate = uint16_t(low_surrogate << 8 | low_surrogate >> 8);
          }
          *utf16_output++ = char16_t(high_surrogate);
          *utf16_output++ = char16_t(low_surrogate);
        }
      }
      buf += k;
    }
  }

  // check for invalid input
  if (__lasx_xbnz_v(forbidden_bytemask)) {
    return std::make_pair(nullptr, reinterpret_cast<char16_t *>(utf16_output));
  }
  return std::make_pair(buf, reinterpret_cast<char16_t *>(utf16_output));
}

template <endianness big_endian>
std::pair<result, char16_t *>
lasx_convert_utf32_to_utf16_with_errors(const char32_t *buf, size_t len,
                                        char16_t *utf16_out) {
  uint16_t *utf16_output = reinterpret_cast<uint16_t *>(utf16_out);
  const char32_t *start = buf;
  const char32_t *end = buf + len;

  // Performance degradation when memory address is not 32-byte aligned
  while (((uint64_t)utf16_output & 0x1F) && buf < end) {
    uint32_t word = *buf++;
    if ((word & 0xFFFF0000) == 0) {
      // will not generate a surrogate pair
      if (word >= 0xD800 && word <= 0xDFFF) {
        return std::make_pair(result(error_code::SURROGATE, buf - start - 1),
                              reinterpret_cast<char16_t *>(utf16_output));
      }
      *utf16_output++ = !match_system(big_endian)
                            ? char16_t(word >> 8 | word << 8)
                            : char16_t(word);
    } else {
      // will generate a surrogate pair
      if (word > 0x10FFFF) {
        return std::make_pair(result(error_code::TOO_LARGE, buf - start - 1),
                              reinterpret_cast<char16_t *>(utf16_output));
      }
      word -= 0x10000;
      uint16_t high_surrogate = uint16_t(0xD800 + (word >> 10));
      uint16_t low_surrogate = uint16_t(0xDC00 + (word & 0x3FF));
      if (!match_system(big_endian)) {
        high_surrogate = uint16_t(high_surrogate >> 8 | high_surrogate << 8);
        low_surrogate = uint16_t(low_surrogate << 8 | low_surrogate >> 8);
      }
      *utf16_output++ = char16_t(high_surrogate);
      *utf16_output++ = char16_t(low_surrogate);
    }
  }

  __m256i forbidden_bytemask = __lasx_xvrepli_h(0);
  __m256i v_d800 = __lasx_xvldi(-2600); /*0xD800*/
  __m256i v_dfff = __lasx_xvreplgr2vr_h(uint16_t(0xdfff));
  while (buf + 16 <= end) {
    __m256i in0 = __lasx_xvld(reinterpret_cast<const uint32_t *>(buf), 0);
    __m256i in1 = __lasx_xvld(reinterpret_cast<const uint32_t *>(buf), 32);

    // Check if no bits set above 16th
    if (__lasx_xbz_v(__lasx_xvpickod_h(in1, in0))) {
      __m256i utf16_packed =
          __lasx_xvpermi_d(__lasx_xvpickev_h(in1, in0), 0b11011000);
      forbidden_bytemask = __lasx_xvor_v(
          __lasx_xvand_v(
              __lasx_xvsle_h(utf16_packed, v_dfff),  // utf16_packed <= 0xdfff
              __lasx_xvsle_h(v_d800, utf16_packed)), // utf16_packed >= 0xd800
          forbidden_bytemask);
      if (__lasx_xbnz_v(forbidden_bytemask)) {
        return std::make_pair(result(error_code::SURROGATE, buf - start),
                              reinterpret_cast<char16_t *>(utf16_output));
      }

      if (!match_system(big_endian)) {
        utf16_packed = lasx_swap_bytes(utf16_packed);
      }

      __lasx_xvst(utf16_packed, utf16_output, 0);
      utf16_output += 16;
      buf += 16;
    } else {
      size_t forward = 15;
      size_t k = 0;
      if (size_t(end - buf) < forward + 1) {
        forward = size_t(end - buf - 1);
      }
      for (; k < forward; k++) {
        uint32_t word = buf[k];
        if ((word & 0xFFFF0000) == 0) {
          // will not generate a surrogate pair
          if (word >= 0xD800 && word <= 0xDFFF) {
            return std::make_pair(
                result(error_code::SURROGATE, buf - start + k),
                reinterpret_cast<char16_t *>(utf16_output));
          }
          *utf16_output++ = !match_system(big_endian)
                                ? char16_t(word >> 8 | word << 8)
                                : char16_t(word);
        } else {
          // will generate a surrogate pair
          if (word > 0x10FFFF) {
            return std::make_pair(
                result(error_code::TOO_LARGE, buf - start + k),
                reinterpret_cast<char16_t *>(utf16_output));
          }
          word -= 0x10000;
          uint16_t high_surrogate = uint16_t(0xD800 + (word >> 10));
          uint16_t low_surrogate = uint16_t(0xDC00 + (word & 0x3FF));
          if (!match_system(big_endian)) {
            high_surrogate =
                uint16_t(high_surrogate >> 8 | high_surrogate << 8);
            low_surrogate = uint16_t(low_surrogate << 8 | low_surrogate >> 8);
          }
          *utf16_output++ = char16_t(high_surrogate);
          *utf16_output++ = char16_t(low_surrogate);
        }
      }
      buf += k;
    }
  }

  return std::make_pair(result(error_code::SUCCESS, buf - start),
                        reinterpret_cast<char16_t *>(utf16_output));
}
