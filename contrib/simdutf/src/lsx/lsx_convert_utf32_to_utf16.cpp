template <endianness big_endian>
std::pair<const char32_t *, char16_t *>
lsx_convert_utf32_to_utf16(const char32_t *buf, size_t len,
                           char16_t *utf16_out) {
  uint16_t *utf16_output = reinterpret_cast<uint16_t *>(utf16_out);
  const char32_t *end = buf + len;

  __m128i forbidden_bytemask = __lsx_vrepli_h(0);
  __m128i v_d800 = __lsx_vldi(-2600); /*0xD800*/
  __m128i v_dfff = __lsx_vreplgr2vr_h(uint16_t(0xdfff));
  while (buf + 8 <= end) {
    __m128i in0 = __lsx_vld(reinterpret_cast<const uint32_t *>(buf), 0);
    __m128i in1 = __lsx_vld(reinterpret_cast<const uint32_t *>(buf), 16);

    // Check if no bits set above 16th
    if (__lsx_bz_v(__lsx_vpickod_h(in1, in0))) {
      __m128i utf16_packed = __lsx_vpickev_h(in1, in0);
      forbidden_bytemask = __lsx_vor_v(
          __lsx_vand_v(
              __lsx_vsle_h(utf16_packed, v_dfff),  // utf16_packed <= 0xdfff
              __lsx_vsle_h(v_d800, utf16_packed)), // utf16_packed >= 0xd800
          forbidden_bytemask);

      if (!match_system(big_endian)) {
        utf16_packed = lsx_swap_bytes(utf16_packed);
      }
      __lsx_vst(utf16_packed, utf16_output, 0);
      utf16_output += 8;
      buf += 8;
    } else {
      size_t forward = 3;
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
  if (__lsx_bnz_v(forbidden_bytemask)) {
    return std::make_pair(nullptr, reinterpret_cast<char16_t *>(utf16_output));
  }
  return std::make_pair(buf, reinterpret_cast<char16_t *>(utf16_output));
}

template <endianness big_endian>
std::pair<result, char16_t *>
lsx_convert_utf32_to_utf16_with_errors(const char32_t *buf, size_t len,
                                       char16_t *utf16_out) {
  uint16_t *utf16_output = reinterpret_cast<uint16_t *>(utf16_out);
  const char32_t *start = buf;
  const char32_t *end = buf + len;

  __m128i forbidden_bytemask = __lsx_vrepli_h(0);
  __m128i v_d800 = __lsx_vldi(-2600); /*0xD800*/
  __m128i v_dfff = __lsx_vreplgr2vr_h(uint16_t(0xdfff));

  while (buf + 8 <= end) {
    __m128i in0 = __lsx_vld(reinterpret_cast<const uint32_t *>(buf), 0);
    __m128i in1 = __lsx_vld(reinterpret_cast<const uint32_t *>(buf), 16);
    // Check if no bits set above 16th
    if (__lsx_bz_v(__lsx_vpickod_h(in1, in0))) {
      __m128i utf16_packed = __lsx_vpickev_h(in1, in0);

      forbidden_bytemask = __lsx_vor_v(
          __lsx_vand_v(
              __lsx_vsle_h(utf16_packed, v_dfff),  // utf16_packed <= 0xdfff
              __lsx_vsle_h(v_d800, utf16_packed)), // utf16_packed >= 0xd800
          forbidden_bytemask);
      if (__lsx_bnz_v(forbidden_bytemask)) {
        return std::make_pair(result(error_code::SURROGATE, buf - start),
                              reinterpret_cast<char16_t *>(utf16_output));
      }

      if (!match_system(big_endian)) {
        utf16_packed = lsx_swap_bytes(utf16_packed);
      }

      __lsx_vst(utf16_packed, utf16_output, 0);
      utf16_output += 8;
      buf += 8;
    } else {
      size_t forward = 3;
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
