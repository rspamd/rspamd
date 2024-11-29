template <endianness big_endian>
std::pair<const char16_t *, char32_t *>
lsx_convert_utf16_to_utf32(const char16_t *buf, size_t len,
                           char32_t *utf32_out) {
  uint32_t *utf32_output = reinterpret_cast<uint32_t *>(utf32_out);
  const char16_t *end = buf + len;

  __m128i zero = __lsx_vldi(0);
  __m128i v_f800 = __lsx_vldi(-2568); /*0xF800*/
  __m128i v_d800 = __lsx_vldi(-2600); /*0xD800*/

  while (buf + 8 <= end) {
    __m128i in = __lsx_vld(reinterpret_cast<const uint16_t *>(buf), 0);
    if (!match_system(big_endian)) {
      in = lsx_swap_bytes(in);
    }

    __m128i surrogates_bytemask =
        __lsx_vseq_h(__lsx_vand_v(in, v_f800), v_d800);
    // It might seem like checking for surrogates_bitmask == 0xc000 could help.
    // However, it is likely an uncommon occurrence.
    if (__lsx_bz_v(surrogates_bytemask)) {
      // case: no surrogate pairs, extend all 16-bit code units to 32-bit code
      // units
      __lsx_vst(__lsx_vilvl_h(zero, in), utf32_output, 0);
      __lsx_vst(__lsx_vilvh_h(zero, in), utf32_output, 16);
      utf32_output += 8;
      buf += 8;
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
lsx_convert_utf16_to_utf32_with_errors(const char16_t *buf, size_t len,
                                       char32_t *utf32_out) {
  uint32_t *utf32_output = reinterpret_cast<uint32_t *>(utf32_out);
  const char16_t *start = buf;
  const char16_t *end = buf + len;

  __m128i zero = __lsx_vldi(0);
  __m128i v_f800 = __lsx_vldi(-2568); /*0xF800*/
  __m128i v_d800 = __lsx_vldi(-2600); /*0xD800*/

  while (buf + 8 <= end) {
    __m128i in = __lsx_vld(reinterpret_cast<const uint16_t *>(buf), 0);
    if (!match_system(big_endian)) {
      in = lsx_swap_bytes(in);
    }

    __m128i surrogates_bytemask =
        __lsx_vseq_h(__lsx_vand_v(in, v_f800), v_d800);
    if (__lsx_bz_v(surrogates_bytemask)) {
      // case: no surrogate pairs, extend all 16-bit code units to 32-bit code
      // units
      __lsx_vst(__lsx_vilvl_h(zero, in), utf32_output, 0);
      __lsx_vst(__lsx_vilvh_h(zero, in), utf32_output, 16);
      utf32_output += 8;
      buf += 8;
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
