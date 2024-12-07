template <endianness big_endian>
std::pair<const char16_t *, char32_t *>
lasx_convert_utf16_to_utf32(const char16_t *buf, size_t len,
                            char32_t *utf32_out) {
  uint32_t *utf32_output = reinterpret_cast<uint32_t *>(utf32_out);
  const char16_t *end = buf + len;

  // Performance degradation when memory address is not 32-byte aligned
  while (((uint64_t)utf32_output & 0x1f) && buf < end) {
    uint16_t word =
        !match_system(big_endian) ? scalar::utf16::swap_bytes(buf[0]) : buf[0];
    if ((word & 0xF800) != 0xD800) {
      *utf32_output++ = char32_t(word);
      buf++;
    } else {
      if (buf + 1 >= end) {
        return std::make_pair(nullptr,
                              reinterpret_cast<char32_t *>(utf32_output));
      }
      // must be a surrogate pair
      uint16_t diff = uint16_t(word - 0xD800);
      uint16_t next_word = !match_system(big_endian)
                               ? scalar::utf16::swap_bytes(buf[1])
                               : buf[1];
      uint16_t diff2 = uint16_t(next_word - 0xDC00);
      if ((diff | diff2) > 0x3FF) {
        return std::make_pair(nullptr,
                              reinterpret_cast<char32_t *>(utf32_output));
      }
      uint32_t value = (diff << 10) + diff2 + 0x10000;
      *utf32_output++ = char32_t(value);
      buf += 2;
    }
  }

  __m256i v_f800 = __lasx_xvldi(-2568); /*0xF800*/
  __m256i v_d800 = __lasx_xvldi(-2600); /*0xD800*/

  while (buf + 16 <= end) {
    __m256i in = __lasx_xvld(reinterpret_cast<const uint16_t *>(buf), 0);
    if (!match_system(big_endian)) {
      in = lasx_swap_bytes(in);
    }

    __m256i surrogates_bytemask =
        __lasx_xvseq_h(__lasx_xvand_v(in, v_f800), v_d800);
    // It might seem like checking for surrogates_bitmask == 0xc000 could help.
    // However, it is likely an uncommon occurrence.
    if (__lasx_xbz_v(surrogates_bytemask)) {
      // case: no surrogate pairs, extend all 16-bit code units to 32-bit code
      // units
      __m256i in_hi = __lasx_xvpermi_q(in, in, 0b00000001);
      __lasx_xvst(__lasx_vext2xv_wu_hu(in), utf32_output, 0);
      __lasx_xvst(__lasx_vext2xv_wu_hu(in_hi), utf32_output, 32);
      utf32_output += 16;
      buf += 16;
      // surrogate pair(s) in a register
    } else {
      // Let us do a scalar fallback.
      // It may seem wasteful to use scalar code, but being efficient with SIMD
      // in the presence of surrogate pairs may require non-trivial tables.
      size_t forward = 15;
      size_t k = 0;
      if (size_t(end - buf) < forward + 1) {
        forward = size_t(end - buf - 1);
      }
      for (; k < forward; k++) {
        uint16_t word = !match_system(big_endian)
                            ? scalar::utf16::swap_bytes(buf[k])
                            : buf[k];
        if ((word & 0xF800) != 0xD800) {
          *utf32_output++ = char32_t(word);
        } else {
          // must be a surrogate pair
          uint16_t diff = uint16_t(word - 0xD800);
          uint16_t next_word = !match_system(big_endian)
                                   ? scalar::utf16::swap_bytes(buf[k + 1])
                                   : buf[k + 1];
          k++;
          uint16_t diff2 = uint16_t(next_word - 0xDC00);
          if ((diff | diff2) > 0x3FF) {
            return std::make_pair(nullptr,
                                  reinterpret_cast<char32_t *>(utf32_output));
          }
          uint32_t value = (diff << 10) + diff2 + 0x10000;
          *utf32_output++ = char32_t(value);
        }
      }
      buf += k;
    }
  } // while
  return std::make_pair(buf, reinterpret_cast<char32_t *>(utf32_output));
}

/*
  Returns a pair: a result struct and utf8_output.
  If there is an error, the count field of the result is the position of the
  error. Otherwise, it is the position of the first unprocessed byte in buf
  (even if finished). A scalar routing should carry on the conversion of the
  tail if needed.
*/
template <endianness big_endian>
std::pair<result, char32_t *>
lasx_convert_utf16_to_utf32_with_errors(const char16_t *buf, size_t len,
                                        char32_t *utf32_out) {
  uint32_t *utf32_output = reinterpret_cast<uint32_t *>(utf32_out);
  const char16_t *start = buf;
  const char16_t *end = buf + len;

  // Performance degradation when memory address is not 32-byte aligned
  while (((uint64_t)utf32_output & 0x1f) && buf < end) {
    uint16_t word =
        !match_system(big_endian) ? scalar::utf16::swap_bytes(buf[0]) : buf[0];
    if ((word & 0xF800) != 0xD800) {
      *utf32_output++ = char32_t(word);
      buf++;
    } else if (buf + 1 < end) {
      // must be a surrogate pair
      uint16_t diff = uint16_t(word - 0xD800);
      uint16_t next_word = !match_system(big_endian)
                               ? scalar::utf16::swap_bytes(buf[1])
                               : buf[1];
      uint16_t diff2 = uint16_t(next_word - 0xDC00);
      if ((diff | diff2) > 0x3FF) {
        return std::make_pair(result(error_code::SURROGATE, buf - start),
                              reinterpret_cast<char32_t *>(utf32_output));
      }
      uint32_t value = (diff << 10) + diff2 + 0x10000;
      *utf32_output++ = char32_t(value);
      buf += 2;
    } else {
      return std::make_pair(result(error_code::SURROGATE, buf - start),
                            reinterpret_cast<char32_t *>(utf32_output));
    }
  }

  __m256i v_f800 = __lasx_xvldi(-2568); /*0xF800*/
  __m256i v_d800 = __lasx_xvldi(-2600); /*0xD800*/
  while (buf + 16 <= end) {
    __m256i in = __lasx_xvld(reinterpret_cast<const uint16_t *>(buf), 0);
    if (!match_system(big_endian)) {
      in = lasx_swap_bytes(in);
    }

    __m256i surrogates_bytemask =
        __lasx_xvseq_h(__lasx_xvand_v(in, v_f800), v_d800);
    // It might seem like checking for surrogates_bitmask == 0xc000 could help.
    // However, it is likely an uncommon occurrence.
    if (__lasx_xbz_v(surrogates_bytemask)) {
      // case: no surrogate pairs, extend all 16-bit code units to 32-bit code
      // units
      __m256i in_hi = __lasx_xvpermi_q(in, in, 0b00000001);
      __lasx_xvst(__lasx_vext2xv_wu_hu(in), utf32_output, 0);
      __lasx_xvst(__lasx_vext2xv_wu_hu(in_hi), utf32_output, 32);
      utf32_output += 16;
      buf += 16;
      // surrogate pair(s) in a register
    } else {
      // Let us do a scalar fallback.
      // It may seem wasteful to use scalar code, but being efficient with SIMD
      // in the presence of surrogate pairs may require non-trivial tables.
      size_t forward = 15;
      size_t k = 0;
      if (size_t(end - buf) < forward + 1) {
        forward = size_t(end - buf - 1);
      }
      for (; k < forward; k++) {
        uint16_t word = !match_system(big_endian)
                            ? scalar::utf16::swap_bytes(buf[k])
                            : buf[k];
        if ((word & 0xF800) != 0xD800) {
          *utf32_output++ = char32_t(word);
        } else {
          // must be a surrogate pair
          uint16_t diff = uint16_t(word - 0xD800);
          uint16_t next_word = !match_system(big_endian)
                                   ? scalar::utf16::swap_bytes(buf[k + 1])
                                   : buf[k + 1];
          k++;
          uint16_t diff2 = uint16_t(next_word - 0xDC00);
          if ((diff | diff2) > 0x3FF) {
            return std::make_pair(
                result(error_code::SURROGATE, buf - start + k - 1),
                reinterpret_cast<char32_t *>(utf32_output));
          }
          uint32_t value = (diff << 10) + diff2 + 0x10000;
          *utf32_output++ = char32_t(value);
        }
      }
      buf += k;
    }
  } // while
  return std::make_pair(result(error_code::SUCCESS, buf - start),
                        reinterpret_cast<char32_t *>(utf32_output));
}
