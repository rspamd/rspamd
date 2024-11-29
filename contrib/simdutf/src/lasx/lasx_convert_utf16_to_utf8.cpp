/*
    The vectorized algorithm works on single LASX register i.e., it
    loads eight 16-bit code units.

    We consider three cases:
    1. an input register contains no surrogates and each value
       is in range 0x0000 .. 0x07ff.
    2. an input register contains no surrogates and values are
       is in range 0x0000 .. 0xffff.
    3. an input register contains surrogates --- i.e. codepoints
       can have 16 or 32 bits.

    Ad 1.

    When values are less than 0x0800, it means that a 16-bit code unit
    can be converted into: 1) single UTF8 byte (when it's an ASCII
    char) or 2) two UTF8 bytes.

    For this case we do only some shuffle to obtain these 2-byte
    codes and finally compress the whole LASX register with a single
    shuffle.

    We need 256-entry lookup table to get a compression pattern
    and the number of output bytes in the compressed vector register.
    Each entry occupies 17 bytes.

    Ad 2.

    When values fit in 16-bit code units, but are above 0x07ff, then
    a single word may produce one, two or three UTF8 bytes.

    We prepare data for all these three cases in two registers.
    The first register contains lower two UTF8 bytes (used in all
    cases), while the second one contains just the third byte for
    the three-UTF8-bytes case.

    Finally these two registers are interleaved forming eight-element
    array of 32-bit values. The array spans two LASX registers.
    The bytes from the registers are compressed using two shuffles.

    We need 256-entry lookup table to get a compression pattern
    and the number of output bytes in the compressed vector register.
    Each entry occupies 17 bytes.


    To summarize:
    - We need two 256-entry tables that have 8704 bytes in total.
*/
/*
  Returns a pair: the first unprocessed byte from buf and utf8_output
  A scalar routing should carry on the conversion of the tail.
*/

template <endianness big_endian>
std::pair<const char16_t *, char *>
lasx_convert_utf16_to_utf8(const char16_t *buf, size_t len, char *utf8_out) {
  uint8_t *utf8_output = reinterpret_cast<uint8_t *>(utf8_out);
  const char16_t *end = buf + len;

  const size_t safety_margin =
      12; // to avoid overruns, see issue
          // https://github.com/simdutf/simdutf/issues/92

  __m256i v_07ff = __lasx_xvreplgr2vr_h(uint16_t(0x7ff));
  __m256i zero = __lasx_xvldi(0);
  __m128i zero_128 = __lsx_vldi(0);
  while (buf + 16 + safety_margin <= end) {
    __m256i in = __lasx_xvld(reinterpret_cast<const uint16_t *>(buf), 0);
    if (!match_system(big_endian)) {
      in = lasx_swap_bytes(in);
    }
    if (__lasx_xbnz_h(__lasx_xvslt_hu(
            in, __lasx_xvrepli_h(0x7F)))) { // ASCII fast path!!!!
      // 1. pack the bytes
      __m256i utf8_packed =
          __lasx_xvpermi_d(__lasx_xvpickev_b(in, in), 0b00001000);
      // 2. store (16 bytes)
      __lsx_vst(lasx_extracti128_lo(utf8_packed), utf8_output, 0);
      // 3. adjust pointers
      buf += 16;
      utf8_output += 16;
      continue; // we are done for this round!
    }

    if (__lasx_xbz_v(__lasx_xvslt_hu(v_07ff, in))) {
      // 1. prepare 2-byte values
      // input 16-bit word : [0000|0aaa|aabb|bbbb] x 16
      // expected output   : [110a|aaaa|10bb|bbbb] x 16
      // t0 = [000a|aaaa|bbbb|bb00]
      __m256i t0 = __lasx_xvslli_h(in, 2);
      // t1 = [000a|aaaa|0000|0000]
      __m256i t1 = __lasx_xvand_v(t0, __lasx_xvldi(-2785 /*0x1f00*/));
      // t2 = [0000|0000|00bb|bbbb]
      __m256i t2 = __lasx_xvand_v(in, __lasx_xvrepli_h(0x3f));
      // t3 = [000a|aaaa|00bb|bbbb]
      __m256i t3 = __lasx_xvor_v(t1, t2);
      // t4 = [110a|aaaa|10bb|bbbb]
      __m256i v_c080 = __lasx_xvreplgr2vr_h(uint16_t(0xc080));
      __m256i t4 = __lasx_xvor_v(t3, v_c080);
      // 2. merge ASCII and 2-byte codewords
      __m256i one_byte_bytemask =
          __lasx_xvsle_hu(in, __lasx_xvrepli_h(0x7F /*0x007F*/));
      __m256i utf8_unpacked = __lasx_xvbitsel_v(t4, in, one_byte_bytemask);
      // 3. prepare bitmask for 8-bit lookup
      __m256i mask = __lasx_xvmskltz_h(one_byte_bytemask);
      uint32_t m1 = __lasx_xvpickve2gr_wu(mask, 0);
      uint32_t m2 = __lasx_xvpickve2gr_wu(mask, 4);
      // 4. pack the bytes
      const uint8_t *row1 = &simdutf::tables::utf16_to_utf8::pack_1_2_utf8_bytes
                                [lasx_1_2_utf8_bytes_mask[m1]][0];
      __m128i shuffle1 = __lsx_vld(row1, 1);
      __m128i utf8_packed1 =
          __lsx_vshuf_b(zero_128, lasx_extracti128_lo(utf8_unpacked), shuffle1);

      const uint8_t *row2 = &simdutf::tables::utf16_to_utf8::pack_1_2_utf8_bytes
                                [lasx_1_2_utf8_bytes_mask[m2]][0];
      __m128i shuffle2 = __lsx_vld(row2, 1);
      __m128i utf8_packed2 =
          __lsx_vshuf_b(zero_128, lasx_extracti128_hi(utf8_unpacked), shuffle2);
      // 5. store bytes
      __lsx_vst(utf8_packed1, utf8_output, 0);
      utf8_output += row1[0];

      __lsx_vst(utf8_packed2, utf8_output, 0);
      utf8_output += row2[0];

      buf += 16;
      continue;
    }
    __m256i surrogates_bytemask =
        __lasx_xvseq_h(__lasx_xvand_v(in, __lasx_xvldi(-2568 /*0xF800*/)),
                       __lasx_xvldi(-2600 /*0xD800*/));
    // It might seem like checking for surrogates_bitmask == 0xc000 could help.
    // However, it is likely an uncommon occurrence.
    if (__lasx_xbz_v(surrogates_bytemask)) {
      // case: code units from register produce either 1, 2 or 3 UTF-8 bytes
      /* In this branch we handle three cases:
           1. [0000|0000|0ccc|cccc] => [0ccc|cccc]                           -
         single UFT-8 byte
           2. [0000|0bbb|bbcc|cccc] => [110b|bbbb], [10cc|cccc]              -
         two UTF-8 bytes
           3. [aaaa|bbbb|bbcc|cccc] => [1110|aaaa], [10bb|bbbb], [10cc|cccc] -
         three UTF-8 bytes

          We expand the input word (16-bit) into two code units (32-bit), thus
          we have room for four bytes. However, we need five distinct bit
          layouts. Note that the last byte in cases #2 and #3 is the same.

          We precompute byte 1 for case #1 and the common byte for cases #2 & #3
          in register t2.

          We precompute byte 1 for case #3 and -- **conditionally** --
         precompute either byte 1 for case #2 or byte 2 for case #3. Note that
         they differ by exactly one bit.

          Finally from these two code units we build proper UTF-8 sequence,
         taking into account the case (i.e, the number of bytes to write).
        */
      /**
       * Given [aaaa|bbbb|bbcc|cccc] our goal is to produce:
       * t2 => [0ccc|cccc] [10cc|cccc]
       * s4 => [1110|aaaa] ([110b|bbbb] OR [10bb|bbbb])
       */
      // [aaaa|bbbb|bbcc|cccc] => [bbcc|cccc|bbcc|cccc]
      __m256i t0 = __lasx_xvpickev_b(in, in);
      t0 = __lasx_xvilvl_b(t0, t0);

      // [bbcc|cccc|bbcc|cccc] => [00cc|cccc|00cc|cccc]
      __m256i v_3f7f = __lasx_xvreplgr2vr_h(uint16_t(0x3F7F));
      __m256i t1 = __lasx_xvand_v(t0, v_3f7f);
      // [00cc|cccc|0bcc|cccc] => [10cc|cccc|0bcc|cccc]
      __m256i t2 = __lasx_xvor_v(t1, __lasx_xvldi(-2688));

      // s0: [aaaa|bbbb|bbcc|cccc] => [0000|0000|0000|aaaa]
      __m256i s0 = __lasx_xvsrli_h(in, 12);
      // s1: [aaaa|bbbb|bbcc|cccc] => [0000|bbbb|bb00|0000]
      __m256i s1 = __lasx_xvslli_h(in, 2);
      // s1: [aabb|bbbb|cccc|cc00] => [00bb|bbbb|0000|0000]
      s1 = __lasx_xvand_v(s1, __lasx_xvldi(-2753 /*0x3F00*/));

      // [00bb|bbbb|0000|aaaa]
      __m256i s2 = __lasx_xvor_v(s0, s1);
      // s3: [00bb|bbbb|0000|aaaa] => [11bb|bbbb|1110|aaaa]
      __m256i v_c0e0 = __lasx_xvreplgr2vr_h(uint16_t(0xC0E0));
      __m256i s3 = __lasx_xvor_v(s2, v_c0e0);
      __m256i one_or_two_bytes_bytemask = __lasx_xvsle_hu(in, v_07ff);
      __m256i m0 = __lasx_xvandn_v(one_or_two_bytes_bytemask,
                                   __lasx_xvldi(-2752 /*0x4000*/));
      __m256i s4 = __lasx_xvxor_v(s3, m0);

      // 4. expand code units 16-bit => 32-bit
      __m256i out0 = __lasx_xvilvl_h(s4, t2);
      __m256i out1 = __lasx_xvilvh_h(s4, t2);

      // 5. compress 32-bit code units into 1, 2 or 3 bytes -- 2 x shuffle
      __m256i one_byte_bytemask = __lasx_xvsle_hu(in, __lasx_xvrepli_h(0x7F));
      __m256i one_byte_bytemask_low =
          __lasx_xvilvl_h(one_byte_bytemask, one_byte_bytemask);
      __m256i one_byte_bytemask_high =
          __lasx_xvilvh_h(one_byte_bytemask, one_byte_bytemask);

      __m256i one_or_two_bytes_bytemask_low =
          __lasx_xvilvl_h(one_or_two_bytes_bytemask, zero);
      __m256i one_or_two_bytes_bytemask_high =
          __lasx_xvilvh_h(one_or_two_bytes_bytemask, zero);

      __m256i mask0 = __lasx_xvmskltz_h(
          __lasx_xvor_v(one_or_two_bytes_bytemask_low, one_byte_bytemask_low));
      __m256i mask1 = __lasx_xvmskltz_h(__lasx_xvor_v(
          one_or_two_bytes_bytemask_high, one_byte_bytemask_high));

      uint32_t mask = __lasx_xvpickve2gr_wu(mask0, 0);
      const uint8_t *row0 =
          &simdutf::tables::utf16_to_utf8::pack_1_2_3_utf8_bytes[mask & 0xFF]
                                                                [0];
      __m128i shuffle0 = __lsx_vld(row0, 1);
      __m128i utf8_0 =
          __lsx_vshuf_b(zero_128, lasx_extracti128_lo(out0), shuffle0);
      __lsx_vst(utf8_0, utf8_output, 0);
      utf8_output += row0[0];

      mask = __lasx_xvpickve2gr_wu(mask1, 0);
      const uint8_t *row1 =
          &simdutf::tables::utf16_to_utf8::pack_1_2_3_utf8_bytes[mask & 0xFF]
                                                                [0];
      __m128i shuffle1 = __lsx_vld(row1, 1);
      __m128i utf8_1 =
          __lsx_vshuf_b(zero_128, lasx_extracti128_lo(out1), shuffle1);
      __lsx_vst(utf8_1, utf8_output, 0);
      utf8_output += row1[0];

      mask = __lasx_xvpickve2gr_wu(mask0, 4);
      const uint8_t *row2 =
          &simdutf::tables::utf16_to_utf8::pack_1_2_3_utf8_bytes[mask & 0xFF]
                                                                [0];
      __m128i shuffle2 = __lsx_vld(row2, 1);
      __m128i utf8_2 =
          __lsx_vshuf_b(zero_128, lasx_extracti128_hi(out0), shuffle2);
      __lsx_vst(utf8_2, utf8_output, 0);
      utf8_output += row2[0];

      mask = __lasx_xvpickve2gr_wu(mask1, 4);
      const uint8_t *row3 =
          &simdutf::tables::utf16_to_utf8::pack_1_2_3_utf8_bytes[mask & 0xFF]
                                                                [0];
      __m128i shuffle3 = __lsx_vld(row3, 1);
      __m128i utf8_3 =
          __lsx_vshuf_b(zero_128, lasx_extracti128_hi(out1), shuffle3);
      __lsx_vst(utf8_3, utf8_output, 0);
      utf8_output += row3[0];

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
        if ((word & 0xFF80) == 0) {
          *utf8_output++ = char(word);
        } else if ((word & 0xF800) == 0) {
          *utf8_output++ = char((word >> 6) | 0b11000000);
          *utf8_output++ = char((word & 0b111111) | 0b10000000);
        } else if ((word & 0xF800) != 0xD800) {
          *utf8_output++ = char((word >> 12) | 0b11100000);
          *utf8_output++ = char(((word >> 6) & 0b111111) | 0b10000000);
          *utf8_output++ = char((word & 0b111111) | 0b10000000);
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
                                  reinterpret_cast<char *>(utf8_output));
          }
          uint32_t value = (diff << 10) + diff2 + 0x10000;
          *utf8_output++ = char((value >> 18) | 0b11110000);
          *utf8_output++ = char(((value >> 12) & 0b111111) | 0b10000000);
          *utf8_output++ = char(((value >> 6) & 0b111111) | 0b10000000);
          *utf8_output++ = char((value & 0b111111) | 0b10000000);
        }
      }
      buf += k;
    }
  } // while
  return std::make_pair(buf, reinterpret_cast<char *>(utf8_output));
}

/*
  Returns a pair: a result struct and utf8_output.
  If there is an error, the count field of the result is the position of the
  error. Otherwise, it is the position of the first unprocessed byte in buf
  (even if finished). A scalar routing should carry on the conversion of the
  tail if needed.
*/
template <endianness big_endian>
std::pair<result, char *>
lasx_convert_utf16_to_utf8_with_errors(const char16_t *buf, size_t len,
                                       char *utf8_out) {
  uint8_t *utf8_output = reinterpret_cast<uint8_t *>(utf8_out);
  const char16_t *start = buf;
  const char16_t *end = buf + len;

  const size_t safety_margin =
      12; // to avoid overruns, see issue
          // https://github.com/simdutf/simdutf/issues/92

  __m256i v_07ff = __lasx_xvreplgr2vr_h(uint16_t(0x7ff));
  __m256i zero = __lasx_xvldi(0);
  __m128i zero_128 = __lsx_vldi(0);
  while (buf + 16 + safety_margin <= end) {
    __m256i in = __lasx_xvld(reinterpret_cast<const uint16_t *>(buf), 0);
    if (!match_system(big_endian)) {
      in = lasx_swap_bytes(in);
    }
    if (__lasx_xbnz_h(__lasx_xvslt_hu(
            in, __lasx_xvrepli_h(0x7F)))) { // ASCII fast path!!!!
      // 1. pack the bytes
      __m256i utf8_packed =
          __lasx_xvpermi_d(__lasx_xvpickev_b(in, in), 0b00001000);
      // 2. store (16 bytes)
      __lsx_vst(lasx_extracti128_lo(utf8_packed), utf8_output, 0);
      // 3. adjust pointers
      buf += 16;
      utf8_output += 16;
      continue; // we are done for this round!
    }

    if (__lasx_xbz_v(__lasx_xvslt_hu(v_07ff, in))) {
      // 1. prepare 2-byte values
      // input 16-bit word : [0000|0aaa|aabb|bbbb] x 16
      // expected output   : [110a|aaaa|10bb|bbbb] x 16
      // t0 = [000a|aaaa|bbbb|bb00]
      __m256i t0 = __lasx_xvslli_h(in, 2);
      // t1 = [000a|aaaa|0000|0000]
      __m256i t1 = __lasx_xvand_v(t0, __lasx_xvldi(-2785 /*0x1f00*/));
      // t2 = [0000|0000|00bb|bbbb]
      __m256i t2 = __lasx_xvand_v(in, __lasx_xvrepli_h(0x3f));
      // t3 = [000a|aaaa|00bb|bbbb]
      __m256i t3 = __lasx_xvor_v(t1, t2);
      // t4 = [110a|aaaa|10bb|bbbb]
      __m256i v_c080 = __lasx_xvreplgr2vr_h(uint16_t(0xc080));
      __m256i t4 = __lasx_xvor_v(t3, v_c080);
      // 2. merge ASCII and 2-byte codewords
      __m256i one_byte_bytemask =
          __lasx_xvsle_hu(in, __lasx_xvrepli_h(0x7F /*0x007F*/));
      __m256i utf8_unpacked = __lasx_xvbitsel_v(t4, in, one_byte_bytemask);
      // 3. prepare bitmask for 8-bit lookup
      __m256i mask = __lasx_xvmskltz_h(one_byte_bytemask);
      uint32_t m1 = __lasx_xvpickve2gr_wu(mask, 0);
      uint32_t m2 = __lasx_xvpickve2gr_wu(mask, 4);
      // 4. pack the bytes
      const uint8_t *row1 = &simdutf::tables::utf16_to_utf8::pack_1_2_utf8_bytes
                                [lasx_1_2_utf8_bytes_mask[m1]][0];
      __m128i shuffle1 = __lsx_vld(row1, 1);
      __m128i utf8_packed1 =
          __lsx_vshuf_b(zero_128, lasx_extracti128_lo(utf8_unpacked), shuffle1);

      const uint8_t *row2 = &simdutf::tables::utf16_to_utf8::pack_1_2_utf8_bytes
                                [lasx_1_2_utf8_bytes_mask[m2]][0];
      __m128i shuffle2 = __lsx_vld(row2, 1);
      __m128i utf8_packed2 =
          __lsx_vshuf_b(zero_128, lasx_extracti128_hi(utf8_unpacked), shuffle2);
      // 5. store bytes
      __lsx_vst(utf8_packed1, utf8_output, 0);
      utf8_output += row1[0];

      __lsx_vst(utf8_packed2, utf8_output, 0);
      utf8_output += row2[0];

      buf += 16;
      continue;
    }
    __m256i surrogates_bytemask =
        __lasx_xvseq_h(__lasx_xvand_v(in, __lasx_xvldi(-2568 /*0xF800*/)),
                       __lasx_xvldi(-2600 /*0xD800*/));
    // It might seem like checking for surrogates_bitmask == 0xc000 could help.
    // However, it is likely an uncommon occurrence.
    if (__lasx_xbz_v(surrogates_bytemask)) {
      // case: code units from register produce either 1, 2 or 3 UTF-8 bytes
      /* In this branch we handle three cases:
           1. [0000|0000|0ccc|cccc] => [0ccc|cccc]                           -
         single UFT-8 byte
           2. [0000|0bbb|bbcc|cccc] => [110b|bbbb], [10cc|cccc]              -
         two UTF-8 bytes
           3. [aaaa|bbbb|bbcc|cccc] => [1110|aaaa], [10bb|bbbb], [10cc|cccc] -
         three UTF-8 bytes

          We expand the input word (16-bit) into two code units (32-bit), thus
          we have room for four bytes. However, we need five distinct bit
          layouts. Note that the last byte in cases #2 and #3 is the same.

          We precompute byte 1 for case #1 and the common byte for cases #2 & #3
          in register t2.

          We precompute byte 1 for case #3 and -- **conditionally** --
         precompute either byte 1 for case #2 or byte 2 for case #3. Note that
         they differ by exactly one bit.

          Finally from these two code units we build proper UTF-8 sequence,
         taking into account the case (i.e, the number of bytes to write).
        */
      /**
       * Given [aaaa|bbbb|bbcc|cccc] our goal is to produce:
       * t2 => [0ccc|cccc] [10cc|cccc]
       * s4 => [1110|aaaa] ([110b|bbbb] OR [10bb|bbbb])
       */
      // [aaaa|bbbb|bbcc|cccc] => [bbcc|cccc|bbcc|cccc]
      __m256i t0 = __lasx_xvpickev_b(in, in);
      t0 = __lasx_xvilvl_b(t0, t0);

      // [bbcc|cccc|bbcc|cccc] => [00cc|cccc|00cc|cccc]
      __m256i v_3f7f = __lasx_xvreplgr2vr_h(uint16_t(0x3F7F));
      __m256i t1 = __lasx_xvand_v(t0, v_3f7f);
      // [00cc|cccc|0bcc|cccc] => [10cc|cccc|0bcc|cccc]
      __m256i t2 = __lasx_xvor_v(t1, __lasx_xvldi(-2688));

      // s0: [aaaa|bbbb|bbcc|cccc] => [0000|0000|0000|aaaa]
      __m256i s0 = __lasx_xvsrli_h(in, 12);
      // s1: [aaaa|bbbb|bbcc|cccc] => [0000|bbbb|bb00|0000]
      __m256i s1 = __lasx_xvslli_h(in, 2);
      // s1: [aabb|bbbb|cccc|cc00] => [00bb|bbbb|0000|0000]
      s1 = __lasx_xvand_v(s1, __lasx_xvldi(-2753 /*0x3F00*/));

      // [00bb|bbbb|0000|aaaa]
      __m256i s2 = __lasx_xvor_v(s0, s1);
      // s3: [00bb|bbbb|0000|aaaa] => [11bb|bbbb|1110|aaaa]
      __m256i v_c0e0 = __lasx_xvreplgr2vr_h(uint16_t(0xC0E0));
      __m256i s3 = __lasx_xvor_v(s2, v_c0e0);
      __m256i one_or_two_bytes_bytemask = __lasx_xvsle_hu(in, v_07ff);
      __m256i m0 = __lasx_xvandn_v(one_or_two_bytes_bytemask,
                                   __lasx_xvldi(-2752 /*0x4000*/));
      __m256i s4 = __lasx_xvxor_v(s3, m0);

      // 4. expand code units 16-bit => 32-bit
      __m256i out0 = __lasx_xvilvl_h(s4, t2);
      __m256i out1 = __lasx_xvilvh_h(s4, t2);

      // 5. compress 32-bit code units into 1, 2 or 3 bytes -- 2 x shuffle
      __m256i one_byte_bytemask = __lasx_xvsle_hu(in, __lasx_xvrepli_h(0x7F));
      __m256i one_byte_bytemask_low =
          __lasx_xvilvl_h(one_byte_bytemask, one_byte_bytemask);
      __m256i one_byte_bytemask_high =
          __lasx_xvilvh_h(one_byte_bytemask, one_byte_bytemask);

      __m256i one_or_two_bytes_bytemask_low =
          __lasx_xvilvl_h(one_or_two_bytes_bytemask, zero);
      __m256i one_or_two_bytes_bytemask_high =
          __lasx_xvilvh_h(one_or_two_bytes_bytemask, zero);

      __m256i mask0 = __lasx_xvmskltz_h(
          __lasx_xvor_v(one_or_two_bytes_bytemask_low, one_byte_bytemask_low));
      __m256i mask1 = __lasx_xvmskltz_h(__lasx_xvor_v(
          one_or_two_bytes_bytemask_high, one_byte_bytemask_high));

      uint32_t mask = __lasx_xvpickve2gr_wu(mask0, 0);
      const uint8_t *row0 =
          &simdutf::tables::utf16_to_utf8::pack_1_2_3_utf8_bytes[mask & 0xFF]
                                                                [0];
      __m128i shuffle0 = __lsx_vld(row0, 1);
      __m128i utf8_0 =
          __lsx_vshuf_b(zero_128, lasx_extracti128_lo(out0), shuffle0);
      __lsx_vst(utf8_0, utf8_output, 0);
      utf8_output += row0[0];

      mask = __lasx_xvpickve2gr_wu(mask1, 0);
      const uint8_t *row1 =
          &simdutf::tables::utf16_to_utf8::pack_1_2_3_utf8_bytes[mask & 0xFF]
                                                                [0];
      __m128i shuffle1 = __lsx_vld(row1, 1);
      __m128i utf8_1 =
          __lsx_vshuf_b(zero_128, lasx_extracti128_lo(out1), shuffle1);
      __lsx_vst(utf8_1, utf8_output, 0);
      utf8_output += row1[0];

      mask = __lasx_xvpickve2gr_wu(mask0, 4);
      const uint8_t *row2 =
          &simdutf::tables::utf16_to_utf8::pack_1_2_3_utf8_bytes[mask & 0xFF]
                                                                [0];
      __m128i shuffle2 = __lsx_vld(row2, 1);
      __m128i utf8_2 =
          __lsx_vshuf_b(zero_128, lasx_extracti128_hi(out0), shuffle2);
      __lsx_vst(utf8_2, utf8_output, 0);
      utf8_output += row2[0];

      mask = __lasx_xvpickve2gr_wu(mask1, 4);
      const uint8_t *row3 =
          &simdutf::tables::utf16_to_utf8::pack_1_2_3_utf8_bytes[mask & 0xFF]
                                                                [0];
      __m128i shuffle3 = __lsx_vld(row3, 1);
      __m128i utf8_3 =
          __lsx_vshuf_b(zero_128, lasx_extracti128_hi(out1), shuffle3);
      __lsx_vst(utf8_3, utf8_output, 0);
      utf8_output += row3[0];

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
        if ((word & 0xFF80) == 0) {
          *utf8_output++ = char(word);
        } else if ((word & 0xF800) == 0) {
          *utf8_output++ = char((word >> 6) | 0b11000000);
          *utf8_output++ = char((word & 0b111111) | 0b10000000);
        } else if ((word & 0xF800) != 0xD800) {
          *utf8_output++ = char((word >> 12) | 0b11100000);
          *utf8_output++ = char(((word >> 6) & 0b111111) | 0b10000000);
          *utf8_output++ = char((word & 0b111111) | 0b10000000);
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
                reinterpret_cast<char *>(utf8_output));
          }
          uint32_t value = (diff << 10) + diff2 + 0x10000;
          *utf8_output++ = char((value >> 18) | 0b11110000);
          *utf8_output++ = char(((value >> 12) & 0b111111) | 0b10000000);
          *utf8_output++ = char(((value >> 6) & 0b111111) | 0b10000000);
          *utf8_output++ = char((value & 0b111111) | 0b10000000);
        }
      }
      buf += k;
    }
  } // while

  return std::make_pair(result(error_code::SUCCESS, buf - start),
                        reinterpret_cast<char *>(utf8_output));
}
