/*
    The vectorized algorithm works on single SSE register i.e., it
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
    codes and finally compress the whole SSE register with a single
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
    array of 32-bit values. The array spans two SSE registers.
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
lsx_convert_utf16_to_utf8(const char16_t *buf, size_t len, char *utf8_out) {
  uint8_t *utf8_output = reinterpret_cast<uint8_t *>(utf8_out);
  const char16_t *end = buf + len;

  const size_t safety_margin =
      12; // to avoid overruns, see issue
          // https://github.com/simdutf/simdutf/issues/92

  __m128i v_07ff = __lsx_vreplgr2vr_h(uint16_t(0x7ff));
  while (buf + 16 + safety_margin <= end) {
    __m128i in = __lsx_vld(reinterpret_cast<const uint16_t *>(buf), 0);
    if (!match_system(big_endian)) {
      in = lsx_swap_bytes(in);
    }
    if (__lsx_bz_v(
            __lsx_vslt_hu(__lsx_vrepli_h(0x7F), in))) { // ASCII fast path!!!!
      // It is common enough that we have sequences of 16 consecutive ASCII
      // characters.
      __m128i nextin = __lsx_vld(reinterpret_cast<const uint16_t *>(buf), 16);
      if (!match_system(big_endian)) {
        nextin = lsx_swap_bytes(nextin);
      }
      if (__lsx_bz_v(__lsx_vslt_hu(__lsx_vrepli_h(0x7F), nextin))) {
        // 1. pack the bytes
        // obviously suboptimal.
        __m128i utf8_packed = __lsx_vpickev_b(nextin, in);
        // 2. store (16 bytes)
        __lsx_vst(utf8_packed, utf8_output, 0);
        // 3. adjust pointers
        buf += 16;
        utf8_output += 16;
        continue; // we are done for this round!
      } else {
        // 1. pack the bytes
        // obviously suboptimal.
        __m128i utf8_packed = __lsx_vpickev_b(in, in);
        // 2. store (8 bytes)
        __lsx_vst(utf8_packed, utf8_output, 0);
        // 3. adjust pointers
        buf += 8;
        utf8_output += 8;
        in = nextin;
      }
    }

    __m128i zero = __lsx_vldi(0);
    if (__lsx_bz_v(__lsx_vslt_hu(v_07ff, in))) {
      // 1. prepare 2-byte values
      // input 16-bit word : [0000|0aaa|aabb|bbbb] x 8
      // expected output   : [110a|aaaa|10bb|bbbb] x 8
      // t0 = [000a|aaaa|bbbb|bb00]
      __m128i t0 = __lsx_vslli_h(in, 2);
      // t1 = [000a|aaaa|0000|0000]
      __m128i t1 = __lsx_vand_v(t0, __lsx_vldi(-2785 /*0x1f00*/));
      // t2 = [0000|0000|00bb|bbbb]
      __m128i t2 = __lsx_vand_v(in, __lsx_vrepli_h(0x3f));
      // t3 = [000a|aaaa|00bb|bbbb]
      __m128i t3 = __lsx_vor_v(t1, t2);
      // t4 = [110a|aaaa|10bb|bbbb]
      __m128i v_c080 = __lsx_vreplgr2vr_h(uint16_t(0xc080));
      __m128i t4 = __lsx_vor_v(t3, v_c080);
      // 2. merge ASCII and 2-byte codewords
      __m128i one_byte_bytemask =
          __lsx_vsle_hu(in, __lsx_vrepli_h(0x7F /*0x007F*/));
      __m128i utf8_unpacked = __lsx_vbitsel_v(t4, in, one_byte_bytemask);
      // 3. prepare bitmask for 8-bit lookup
      uint32_t m2 = __lsx_vpickve2gr_bu(__lsx_vmskltz_h(one_byte_bytemask), 0);
      // 4. pack the bytes
      const uint8_t *row = &simdutf::tables::utf16_to_utf8::pack_1_2_utf8_bytes
                               [lsx_1_2_utf8_bytes_mask[m2]][0];
      __m128i shuffle = __lsx_vld(row, 1);
      __m128i utf8_packed = __lsx_vshuf_b(zero, utf8_unpacked, shuffle);
      // 5. store bytes
      __lsx_vst(utf8_packed, utf8_output, 0);
      // 6. adjust pointers
      buf += 8;
      utf8_output += row[0];
      continue;
    }
    __m128i surrogates_bytemask =
        __lsx_vseq_h(__lsx_vand_v(in, __lsx_vldi(-2568 /*0xF800*/)),
                     __lsx_vldi(-2600 /*0xD800*/));
    // It might seem like checking for surrogates_bitmask == 0xc000 could help.
    // However, it is likely an uncommon occurrence.
    if (__lsx_bz_v(surrogates_bytemask)) {
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
      __m128i t0 = __lsx_vpickev_b(in, in);
      t0 = __lsx_vilvl_b(t0, t0);

      // [bbcc|cccc|bbcc|cccc] => [00cc|cccc|00cc|cccc]
      __m128i v_3f7f = __lsx_vreplgr2vr_h(uint16_t(0x3F7F));
      __m128i t1 = __lsx_vand_v(t0, v_3f7f);
      // [00cc|cccc|0bcc|cccc] => [10cc|cccc|0bcc|cccc]
      __m128i t2 = __lsx_vor_v(t1, __lsx_vldi(-2688 /*0x8000*/));

      // s0: [aaaa|bbbb|bbcc|cccc] => [0000|0000|0000|aaaa]
      __m128i s0 = __lsx_vsrli_h(in, 12);
      // s1: [aaaa|bbbb|bbcc|cccc] => [0000|bbbb|bb00|0000]
      __m128i s1 = __lsx_vslli_h(in, 2);
      // s1: [aabb|bbbb|cccc|cc00] => [00bb|bbbb|0000|0000]
      s1 = __lsx_vand_v(s1, __lsx_vldi(-2753 /*0x3F00*/));

      // [00bb|bbbb|0000|aaaa]
      __m128i s2 = __lsx_vor_v(s0, s1);
      // s3: [00bb|bbbb|0000|aaaa] => [11bb|bbbb|1110|aaaa]
      __m128i v_c0e0 = __lsx_vreplgr2vr_h(uint16_t(0xC0E0));
      __m128i s3 = __lsx_vor_v(s2, v_c0e0);
      __m128i one_or_two_bytes_bytemask = __lsx_vsle_hu(in, v_07ff);
      __m128i m0 = __lsx_vandn_v(one_or_two_bytes_bytemask,
                                 __lsx_vldi(-2752 /*0x4000*/));
      __m128i s4 = __lsx_vxor_v(s3, m0);

      // 4. expand code units 16-bit => 32-bit
      __m128i out0 = __lsx_vilvl_h(s4, t2);
      __m128i out1 = __lsx_vilvh_h(s4, t2);

      // 5. compress 32-bit code units into 1, 2 or 3 bytes -- 2 x shuffle
      __m128i one_byte_bytemask = __lsx_vsle_hu(in, __lsx_vrepli_h(0x7F));

      __m128i one_or_two_bytes_bytemask_low =
          __lsx_vilvl_h(one_or_two_bytes_bytemask, zero);
      __m128i one_or_two_bytes_bytemask_high =
          __lsx_vilvh_h(one_or_two_bytes_bytemask, zero);

      __m128i one_byte_bytemask_low =
          __lsx_vilvl_h(one_byte_bytemask, one_byte_bytemask);
      __m128i one_byte_bytemask_high =
          __lsx_vilvh_h(one_byte_bytemask, one_byte_bytemask);

      const uint32_t mask0 = __lsx_vpickve2gr_bu(
          __lsx_vmskltz_h(__lsx_vor_v(one_or_two_bytes_bytemask_low,
                                      one_byte_bytemask_low)),
          0);
      const uint32_t mask1 = __lsx_vpickve2gr_bu(
          __lsx_vmskltz_h(__lsx_vor_v(one_or_two_bytes_bytemask_high,
                                      one_byte_bytemask_high)),
          0);

      const uint8_t *row0 =
          &simdutf::tables::utf16_to_utf8::pack_1_2_3_utf8_bytes[mask0][0];
      __m128i shuffle0 = __lsx_vld(row0, 1);
      __m128i utf8_0 = __lsx_vshuf_b(zero, out0, shuffle0);

      const uint8_t *row1 =
          &simdutf::tables::utf16_to_utf8::pack_1_2_3_utf8_bytes[mask1][0];
      __m128i shuffle1 = __lsx_vld(row1, 1);
      __m128i utf8_1 = __lsx_vshuf_b(zero, out1, shuffle1);

      __lsx_vst(utf8_0, utf8_output, 0);
      utf8_output += row0[0];
      __lsx_vst(utf8_1, utf8_output, 0);
      utf8_output += row1[0];

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
lsx_convert_utf16_to_utf8_with_errors(const char16_t *buf, size_t len,
                                      char *utf8_out) {
  uint8_t *utf8_output = reinterpret_cast<uint8_t *>(utf8_out);
  const char16_t *start = buf;
  const char16_t *end = buf + len;

  const size_t safety_margin =
      12; // to avoid overruns, see issue
          // https://github.com/simdutf/simdutf/issues/92
  while (buf + 16 + safety_margin <= end) {
    __m128i in = __lsx_vld(reinterpret_cast<const uint16_t *>(buf), 0);
    if (!match_system(big_endian)) {
      in = lsx_swap_bytes(in);
    }
    if (__lsx_bz_v(
            __lsx_vslt_hu(__lsx_vrepli_h(0x7F), in))) { // ASCII fast path!!!!
      // It is common enough that we have sequences of 16 consecutive ASCII
      // characters.
      __m128i nextin = __lsx_vld(reinterpret_cast<const uint16_t *>(buf), 16);
      if (!match_system(big_endian)) {
        nextin = lsx_swap_bytes(nextin);
      }
      if (__lsx_bz_v(__lsx_vslt_hu(__lsx_vrepli_h(0x7F), nextin))) {
        // 1. pack the bytes
        // obviously suboptimal.
        __m128i utf8_packed = __lsx_vpickev_b(nextin, in);
        // 2. store (16 bytes)
        __lsx_vst(utf8_packed, utf8_output, 0);
        // 3. adjust pointers
        buf += 16;
        utf8_output += 16;
        continue; // we are done for this round!
      } else {
        // 1. pack the bytes
        // obviously suboptimal.
        __m128i utf8_packed = __lsx_vpickev_b(in, in);
        // 2. store (8 bytes)
        __lsx_vst(utf8_packed, utf8_output, 0);
        // 3. adjust pointers
        buf += 8;
        utf8_output += 8;
        in = nextin;
      }
    }

    __m128i v_07ff = __lsx_vreplgr2vr_h(uint16_t(0x7ff));
    __m128i zero = __lsx_vldi(0);
    if (__lsx_bz_v(__lsx_vslt_hu(v_07ff, in))) {
      // 1. prepare 2-byte values
      // input 16-bit word : [0000|0aaa|aabb|bbbb] x 8
      // expected output   : [110a|aaaa|10bb|bbbb] x 8
      // t0 = [000a|aaaa|bbbb|bb00]
      __m128i t0 = __lsx_vslli_h(in, 2);
      // t1 = [000a|aaaa|0000|0000]
      __m128i t1 = __lsx_vand_v(t0, __lsx_vldi(-2785 /*0x1f00*/));
      // t2 = [0000|0000|00bb|bbbb]
      __m128i t2 = __lsx_vand_v(in, __lsx_vrepli_h(0x3f));
      // t3 = [000a|aaaa|00bb|bbbb]
      __m128i t3 = __lsx_vor_v(t1, t2);
      // t4 = [110a|aaaa|10bb|bbbb]
      __m128i v_c080 = __lsx_vreplgr2vr_h(uint16_t(0xc080));
      __m128i t4 = __lsx_vor_v(t3, v_c080);
      // 2. merge ASCII and 2-byte codewords
      __m128i one_byte_bytemask =
          __lsx_vsle_hu(in, __lsx_vrepli_h(0x7F /*0x007F*/));
      __m128i utf8_unpacked = __lsx_vbitsel_v(t4, in, one_byte_bytemask);
      // 3. prepare bitmask for 8-bit lookup
      uint32_t m2 = __lsx_vpickve2gr_bu(__lsx_vmskltz_h(one_byte_bytemask), 0);
      // 4. pack the bytes
      const uint8_t *row = &simdutf::tables::utf16_to_utf8::pack_1_2_utf8_bytes
                               [lsx_1_2_utf8_bytes_mask[m2]][0];
      __m128i shuffle = __lsx_vld(row, 1);
      __m128i utf8_packed = __lsx_vshuf_b(zero, utf8_unpacked, shuffle);
      // 5. store bytes
      __lsx_vst(utf8_packed, utf8_output, 0);
      // 6. adjust pointers
      buf += 8;
      utf8_output += row[0];
      continue;
    }
    __m128i surrogates_bytemask =
        __lsx_vseq_h(__lsx_vand_v(in, __lsx_vldi(-2568 /*0xF800*/)),
                     __lsx_vldi(-2600 /*0xD800*/));
    // It might seem like checking for surrogates_bitmask == 0xc000 could help.
    // However, it is likely an uncommon occurrence.
    if (__lsx_bz_v(surrogates_bytemask)) {
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
      __m128i t0 = __lsx_vpickev_b(in, in);
      t0 = __lsx_vilvl_b(t0, t0);

      // [bbcc|cccc|bbcc|cccc] => [00cc|cccc|00cc|cccc]
      __m128i v_3f7f = __lsx_vreplgr2vr_h(uint16_t(0x3F7F));
      __m128i t1 = __lsx_vand_v(t0, v_3f7f);
      // [00cc|cccc|0bcc|cccc] => [10cc|cccc|0bcc|cccc]
      __m128i t2 = __lsx_vor_v(t1, __lsx_vldi(-2688));

      // s0: [aaaa|bbbb|bbcc|cccc] => [0000|0000|0000|aaaa]
      __m128i s0 = __lsx_vsrli_h(in, 12);
      // s1: [aaaa|bbbb|bbcc|cccc] => [0000|bbbb|bb00|0000]
      __m128i s1 = __lsx_vslli_h(in, 2);
      // s1: [aabb|bbbb|cccc|cc00] => [00bb|bbbb|0000|0000]
      s1 = __lsx_vand_v(s1, __lsx_vldi(-2753 /*0x3F00*/));

      // [00bb|bbbb|0000|aaaa]
      __m128i s2 = __lsx_vor_v(s0, s1);
      // s3: [00bb|bbbb|0000|aaaa] => [11bb|bbbb|1110|aaaa]
      __m128i v_c0e0 = __lsx_vreplgr2vr_h(uint16_t(0xC0E0));
      __m128i s3 = __lsx_vor_v(s2, v_c0e0);
      __m128i one_or_two_bytes_bytemask = __lsx_vsle_hu(in, v_07ff);
      __m128i m0 = __lsx_vandn_v(one_or_two_bytes_bytemask,
                                 __lsx_vldi(-2752 /*0x4000*/));
      __m128i s4 = __lsx_vxor_v(s3, m0);

      // 4. expand code units 16-bit => 32-bit
      __m128i out0 = __lsx_vilvl_h(s4, t2);
      __m128i out1 = __lsx_vilvh_h(s4, t2);

      // 5. compress 32-bit code units into 1, 2 or 3 bytes -- 2 x shuffle
      __m128i one_byte_bytemask = __lsx_vsle_hu(in, __lsx_vrepli_h(0x7F));

      __m128i one_or_two_bytes_bytemask_low =
          __lsx_vilvl_h(one_or_two_bytes_bytemask, zero);
      __m128i one_or_two_bytes_bytemask_high =
          __lsx_vilvh_h(one_or_two_bytes_bytemask, zero);

      __m128i one_byte_bytemask_low =
          __lsx_vilvl_h(one_byte_bytemask, one_byte_bytemask);
      __m128i one_byte_bytemask_high =
          __lsx_vilvh_h(one_byte_bytemask, one_byte_bytemask);

      const uint32_t mask0 = __lsx_vpickve2gr_bu(
          __lsx_vmskltz_h(__lsx_vor_v(one_or_two_bytes_bytemask_low,
                                      one_byte_bytemask_low)),
          0);
      const uint32_t mask1 = __lsx_vpickve2gr_bu(
          __lsx_vmskltz_h(__lsx_vor_v(one_or_two_bytes_bytemask_high,
                                      one_byte_bytemask_high)),
          0);

      const uint8_t *row0 =
          &simdutf::tables::utf16_to_utf8::pack_1_2_3_utf8_bytes[mask0][0];
      __m128i shuffle0 = __lsx_vld(row0, 1);
      __m128i utf8_0 = __lsx_vshuf_b(zero, out0, shuffle0);

      const uint8_t *row1 =
          &simdutf::tables::utf16_to_utf8::pack_1_2_3_utf8_bytes[mask1][0];
      __m128i shuffle1 = __lsx_vld(row1, 1);
      __m128i utf8_1 = __lsx_vshuf_b(zero, out1, shuffle1);

      __lsx_vst(utf8_0, utf8_output, 0);
      utf8_output += row0[0];
      __lsx_vst(utf8_1, utf8_output, 0);
      utf8_output += row1[0];

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
