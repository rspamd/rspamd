std::pair<const char32_t *, char *>
lsx_convert_utf32_to_utf8(const char32_t *buf, size_t len, char *utf8_out) {
  uint8_t *utf8_output = reinterpret_cast<uint8_t *>(utf8_out);
  const char32_t *end = buf + len;

  __m128i v_c080 = __lsx_vreplgr2vr_h(uint16_t(0xC080));
  __m128i v_07ff = __lsx_vreplgr2vr_h(uint16_t(0x7FF));
  __m128i v_dfff = __lsx_vreplgr2vr_h(uint16_t(0xDFFF));
  __m128i v_d800 = __lsx_vldi(-2600); /*0xD800*/
  __m128i forbidden_bytemask = __lsx_vldi(0x0);

  const size_t safety_margin =
      12; // to avoid overruns, see issue
          // https://github.com/simdutf/simdutf/issues/92

  while (buf + 16 + safety_margin < end) {
    __m128i in = __lsx_vld(reinterpret_cast<const uint32_t *>(buf), 0);
    __m128i nextin = __lsx_vld(reinterpret_cast<const uint32_t *>(buf), 16);

    // Check if no bits set above 16th
    if (__lsx_bz_v(__lsx_vpickod_h(in, nextin))) {
      // Pack UTF-32 to UTF-16 safely (without surrogate pairs)
      // Apply UTF-16 => UTF-8 routine (lsx_convert_utf16_to_utf8.cpp)
      __m128i utf16_packed = __lsx_vpickev_h(nextin, in);

      if (__lsx_bz_v(__lsx_vslt_hu(__lsx_vrepli_h(0x7F),
                                   utf16_packed))) { // ASCII fast path!!!!
        // 1. pack the bytes
        // obviously suboptimal.
        __m128i utf8_packed = __lsx_vpickev_b(utf16_packed, utf16_packed);
        // 2. store (8 bytes)
        __lsx_vst(utf8_packed, utf8_output, 0);
        // 3. adjust pointers
        buf += 8;
        utf8_output += 8;
        continue; // we are done for this round!
      }
      __m128i zero = __lsx_vldi(0);
      if (__lsx_bz_v(__lsx_vslt_hu(v_07ff, utf16_packed))) {
        // 1. prepare 2-byte values
        // input 16-bit word : [0000|0aaa|aabb|bbbb] x 8
        // expected output   : [110a|aaaa|10bb|bbbb] x 8

        // t0 = [000a|aaaa|bbbb|bb00]
        const __m128i t0 = __lsx_vslli_h(utf16_packed, 2);
        // t1 = [000a|aaaa|0000|0000]
        const __m128i t1 = __lsx_vand_v(t0, __lsx_vldi(-2785 /*0x1f00*/));
        // t2 = [0000|0000|00bb|bbbb]
        const __m128i t2 = __lsx_vand_v(utf16_packed, __lsx_vrepli_h(0x3f));
        // t3 = [000a|aaaa|00bb|bbbb]
        const __m128i t3 = __lsx_vor_v(t1, t2);
        // t4 = [110a|aaaa|10bb|bbbb]
        const __m128i t4 = __lsx_vor_v(t3, v_c080);
        // 2. merge ASCII and 2-byte codewords
        __m128i one_byte_bytemask =
            __lsx_vsle_hu(utf16_packed, __lsx_vrepli_h(0x7F /*0x007F*/));
        __m128i utf8_unpacked =
            __lsx_vbitsel_v(t4, utf16_packed, one_byte_bytemask);
        // 3. prepare bitmask for 8-bit lookup
        uint32_t m2 =
            __lsx_vpickve2gr_bu(__lsx_vmskltz_h(one_byte_bytemask), 0);
        // 4. pack the bytes
        const uint8_t *row =
            &simdutf::tables::utf16_to_utf8::pack_1_2_utf8_bytes
                [lsx_1_2_utf8_bytes_mask[m2]][0];
        __m128i shuffle = __lsx_vld(row, 1);
        __m128i utf8_packed = __lsx_vshuf_b(zero, utf8_unpacked, shuffle);
        // 5. store bytes
        __lsx_vst(utf8_packed, utf8_output, 0);

        // 6. adjust pointers
        buf += 8;
        utf8_output += row[0];
        continue;
      } else {
        // case: code units from register produce either 1, 2 or 3 UTF-8 bytes
        forbidden_bytemask = __lsx_vor_v(
            __lsx_vand_v(
                __lsx_vsle_h(utf16_packed, v_dfff),  // utf16_packed <= 0xdfff
                __lsx_vsle_h(v_d800, utf16_packed)), // utf16_packed >= 0xd800
            forbidden_bytemask);
        /* In this branch we handle three cases:
    1. [0000|0000|0ccc|cccc] => [0ccc|cccc]                           - single
    UFT-8 byte
    2. [0000|0bbb|bbcc|cccc] => [110b|bbbb], [10cc|cccc]              - two
    UTF-8 bytes
    3. [aaaa|bbbb|bbcc|cccc] => [1110|aaaa], [10bb|bbbb], [10cc|cccc] - three
    UTF-8 bytes

    We expand the input word (16-bit) into two code units (32-bit), thus
    we have room for four bytes. However, we need five distinct bit
    layouts. Note that the last byte in cases #2 and #3 is the same.

    We precompute byte 1 for case #1 and the common byte for cases #2 & #3
    in register t2.

    We precompute byte 1 for case #3 and -- **conditionally** -- precompute
    either byte 1 for case #2 or byte 2 for case #3. Note that they
    differ by exactly one bit.

    Finally from these two code units we build proper UTF-8 sequence, taking
    into account the case (i.e, the number of bytes to write).
  */
        /**
         * Given [aaaa|bbbb|bbcc|cccc] our goal is to produce:
         * t2 => [0ccc|cccc] [10cc|cccc]
         * s4 => [1110|aaaa] ([110b|bbbb] OR [10bb|bbbb])
         */
        // [aaaa|bbbb|bbcc|cccc] => [bbcc|cccc|bbcc|cccc]
        __m128i t0 = __lsx_vpickev_b(utf16_packed, utf16_packed);
        t0 = __lsx_vilvl_b(t0, t0);
        // [bbcc|cccc|bbcc|cccc] => [00cc|cccc|0bcc|cccc]
        __m128i v_3f7f = __lsx_vreplgr2vr_h(uint16_t(0x3F7F));
        __m128i t1 = __lsx_vand_v(t0, v_3f7f);
        // [00cc|cccc|0bcc|cccc] => [10cc|cccc|0bcc|cccc]
        __m128i t2 = __lsx_vor_v(t1, __lsx_vldi(-2688 /*0x8000*/));

        // s0: [aaaa|bbbb|bbcc|cccc] => [0000|0000|0000|aaaa]
        __m128i s0 = __lsx_vsrli_h(utf16_packed, 12);
        // s1: [aaaa|bbbb|bbcc|cccc] => [0000|bbbb|bb00|0000]
        __m128i s1 = __lsx_vslli_h(utf16_packed, 2);
        // [0000|bbbb|bb00|0000] => [00bb|bbbb|0000|0000]
        s1 = __lsx_vand_v(s1, __lsx_vldi(-2753 /*0x3F00*/));
        // [00bb|bbbb|0000|aaaa]
        __m128i s2 = __lsx_vor_v(s0, s1);
        // s3: [00bb|bbbb|0000|aaaa] => [11bb|bbbb|1110|aaaa]
        __m128i v_c0e0 = __lsx_vreplgr2vr_h(uint16_t(0xC0E0));
        __m128i s3 = __lsx_vor_v(s2, v_c0e0);
        // __m128i v_07ff = vmovq_n_u16((uint16_t)0x07FF);
        __m128i one_or_two_bytes_bytemask = __lsx_vsle_hu(utf16_packed, v_07ff);
        __m128i m0 = __lsx_vandn_v(one_or_two_bytes_bytemask,
                                   __lsx_vldi(-2752 /*0x4000*/));
        __m128i s4 = __lsx_vxor_v(s3, m0);

        // 4. expand code units 16-bit => 32-bit
        __m128i out0 = __lsx_vilvl_h(s4, t2);
        __m128i out1 = __lsx_vilvh_h(s4, t2);

        // 5. compress 32-bit code units into 1, 2 or 3 bytes -- 2 x shuffle
        __m128i one_byte_bytemask =
            __lsx_vsle_hu(utf16_packed, __lsx_vrepli_h(0x7F));

        __m128i one_or_two_bytes_bytemask_u16_to_u32_low =
            __lsx_vilvl_h(one_or_two_bytes_bytemask, zero);
        __m128i one_or_two_bytes_bytemask_u16_to_u32_high =
            __lsx_vilvh_h(one_or_two_bytes_bytemask, zero);

        __m128i one_byte_bytemask_u16_to_u32_low =
            __lsx_vilvl_h(one_byte_bytemask, one_byte_bytemask);
        __m128i one_byte_bytemask_u16_to_u32_high =
            __lsx_vilvh_h(one_byte_bytemask, one_byte_bytemask);

        const uint32_t mask0 =
            __lsx_vpickve2gr_bu(__lsx_vmskltz_h(__lsx_vor_v(
                                    one_or_two_bytes_bytemask_u16_to_u32_low,
                                    one_byte_bytemask_u16_to_u32_low)),
                                0);
        const uint32_t mask1 =
            __lsx_vpickve2gr_bu(__lsx_vmskltz_h(__lsx_vor_v(
                                    one_or_two_bytes_bytemask_u16_to_u32_high,
                                    one_byte_bytemask_u16_to_u32_high)),
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
      }
      // At least one 32-bit word will produce a surrogate pair in UTF-16 <=>
      // will produce four UTF-8 bytes.
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
        uint32_t word = buf[k];
        if ((word & 0xFFFFFF80) == 0) {
          *utf8_output++ = char(word);
        } else if ((word & 0xFFFFF800) == 0) {
          *utf8_output++ = char((word >> 6) | 0b11000000);
          *utf8_output++ = char((word & 0b111111) | 0b10000000);
        } else if ((word & 0xFFFF0000) == 0) {
          if (word >= 0xD800 && word <= 0xDFFF) {
            return std::make_pair(nullptr,
                                  reinterpret_cast<char *>(utf8_output));
          }
          *utf8_output++ = char((word >> 12) | 0b11100000);
          *utf8_output++ = char(((word >> 6) & 0b111111) | 0b10000000);
          *utf8_output++ = char((word & 0b111111) | 0b10000000);
        } else {
          if (word > 0x10FFFF) {
            return std::make_pair(nullptr,
                                  reinterpret_cast<char *>(utf8_output));
          }
          *utf8_output++ = char((word >> 18) | 0b11110000);
          *utf8_output++ = char(((word >> 12) & 0b111111) | 0b10000000);
          *utf8_output++ = char(((word >> 6) & 0b111111) | 0b10000000);
          *utf8_output++ = char((word & 0b111111) | 0b10000000);
        }
      }
      buf += k;
    }
  } // while

  // check for invalid input
  if (__lsx_bnz_v(forbidden_bytemask)) {
    return std::make_pair(nullptr, reinterpret_cast<char *>(utf8_output));
  }
  return std::make_pair(buf, reinterpret_cast<char *>(utf8_output));
}

std::pair<result, char *>
lsx_convert_utf32_to_utf8_with_errors(const char32_t *buf, size_t len,
                                      char *utf8_out) {
  uint8_t *utf8_output = reinterpret_cast<uint8_t *>(utf8_out);
  const char32_t *start = buf;
  const char32_t *end = buf + len;

  __m128i v_c080 = __lsx_vreplgr2vr_h(uint16_t(0xC080));
  __m128i v_07ff = __lsx_vreplgr2vr_h(uint16_t(0x7FF));
  __m128i v_dfff = __lsx_vreplgr2vr_h(uint16_t(0xDFFF));
  __m128i v_d800 = __lsx_vldi(-2600); /*0xD800*/
  __m128i forbidden_bytemask = __lsx_vldi(0x0);
  const size_t safety_margin =
      12; // to avoid overruns, see issue
          // https://github.com/simdutf/simdutf/issues/92

  while (buf + 16 + safety_margin < end) {
    __m128i in = __lsx_vld(reinterpret_cast<const uint32_t *>(buf), 0);
    __m128i nextin = __lsx_vld(reinterpret_cast<const uint32_t *>(buf), 16);

    // Check if no bits set above 16th
    if (__lsx_bz_v(__lsx_vpickod_h(in, nextin))) {
      // Pack UTF-32 to UTF-16 safely (without surrogate pairs)
      // Apply UTF-16 => UTF-8 routine (lsx_convert_utf16_to_utf8.cpp)
      __m128i utf16_packed = __lsx_vpickev_h(nextin, in);

      if (__lsx_bz_v(__lsx_vslt_hu(__lsx_vrepli_h(0x7F),
                                   utf16_packed))) { // ASCII fast path!!!!
        // 1. pack the bytes
        // obviously suboptimal.
        __m128i utf8_packed = __lsx_vpickev_b(utf16_packed, utf16_packed);
        // 2. store (8 bytes)
        __lsx_vst(utf8_packed, utf8_output, 0);
        // 3. adjust pointers
        buf += 8;
        utf8_output += 8;
        continue; // we are done for this round!
      }
      __m128i zero = __lsx_vldi(0);
      if (__lsx_bz_v(__lsx_vslt_hu(v_07ff, utf16_packed))) {
        // 1. prepare 2-byte values
        // input 16-bit word : [0000|0aaa|aabb|bbbb] x 8
        // expected output   : [110a|aaaa|10bb|bbbb] x 8

        // t0 = [000a|aaaa|bbbb|bb00]
        const __m128i t0 = __lsx_vslli_h(utf16_packed, 2);
        // t1 = [000a|aaaa|0000|0000]
        const __m128i t1 = __lsx_vand_v(t0, __lsx_vldi(-2785 /*0x1f00*/));
        // t2 = [0000|0000|00bb|bbbb]
        const __m128i t2 = __lsx_vand_v(utf16_packed, __lsx_vrepli_h(0x3f));
        // t3 = [000a|aaaa|00bb|bbbb]
        const __m128i t3 = __lsx_vor_v(t1, t2);
        // t4 = [110a|aaaa|10bb|bbbb]
        const __m128i t4 = __lsx_vor_v(t3, v_c080);
        // 2. merge ASCII and 2-byte codewords
        __m128i one_byte_bytemask =
            __lsx_vsle_hu(utf16_packed, __lsx_vrepli_h(0x7F /*0x007F*/));
        __m128i utf8_unpacked =
            __lsx_vbitsel_v(t4, utf16_packed, one_byte_bytemask);
        // 3. prepare bitmask for 8-bit lookup
        uint32_t m2 =
            __lsx_vpickve2gr_bu(__lsx_vmskltz_h(one_byte_bytemask), 0);
        // 4. pack the bytes
        const uint8_t *row =
            &simdutf::tables::utf16_to_utf8::pack_1_2_utf8_bytes
                [lsx_1_2_utf8_bytes_mask[m2]][0];
        __m128i shuffle = __lsx_vld(row, 1);
        __m128i utf8_packed = __lsx_vshuf_b(zero, utf8_unpacked, shuffle);
        // 5. store bytes
        __lsx_vst(utf8_packed, utf8_output, 0);

        // 6. adjust pointers
        buf += 8;
        utf8_output += row[0];
        continue;
      } else {
        // case: code units from register produce either 1, 2 or 3 UTF-8 bytes
        forbidden_bytemask = __lsx_vor_v(
            __lsx_vand_v(
                __lsx_vsle_h(utf16_packed, v_dfff),  // utf16_packed <= 0xdfff
                __lsx_vsle_h(v_d800, utf16_packed)), // utf16_packed >= 0xd800
            forbidden_bytemask);
        if (__lsx_bnz_v(forbidden_bytemask)) {
          return std::make_pair(result(error_code::SURROGATE, buf - start),
                                reinterpret_cast<char *>(utf8_output));
        }
        /* In this branch we handle three cases:
    1. [0000|0000|0ccc|cccc] => [0ccc|cccc]                           - single
    UFT-8 byte
    2. [0000|0bbb|bbcc|cccc] => [110b|bbbb], [10cc|cccc]              - two
    UTF-8 bytes
    3. [aaaa|bbbb|bbcc|cccc] => [1110|aaaa], [10bb|bbbb], [10cc|cccc] - three
    UTF-8 bytes

    We expand the input word (16-bit) into two code units (32-bit), thus
    we have room for four bytes. However, we need five distinct bit
    layouts. Note that the last byte in cases #2 and #3 is the same.

    We precompute byte 1 for case #1 and the common byte for cases #2 & #3
    in register t2.

    We precompute byte 1 for case #3 and -- **conditionally** -- precompute
    either byte 1 for case #2 or byte 2 for case #3. Note that they
    differ by exactly one bit.

    Finally from these two code units we build proper UTF-8 sequence, taking
    into account the case (i.e, the number of bytes to write).
  */
        /**
         * Given [aaaa|bbbb|bbcc|cccc] our goal is to produce:
         * t2 => [0ccc|cccc] [10cc|cccc]
         * s4 => [1110|aaaa] ([110b|bbbb] OR [10bb|bbbb])
         */
        // [aaaa|bbbb|bbcc|cccc] => [bbcc|cccc|bbcc|cccc]
        __m128i t0 = __lsx_vpickev_b(utf16_packed, utf16_packed);
        t0 = __lsx_vilvl_b(t0, t0);
        // [bbcc|cccc|bbcc|cccc] => [00cc|cccc|0bcc|cccc]
        __m128i v_3f7f = __lsx_vreplgr2vr_h(uint16_t(0x3F7F));
        __m128i t1 = __lsx_vand_v(t0, v_3f7f);
        // [00cc|cccc|0bcc|cccc] => [10cc|cccc|0bcc|cccc]
        __m128i t2 = __lsx_vor_v(t1, __lsx_vldi(-2688 /*0x8000*/));

        // s0: [aaaa|bbbb|bbcc|cccc] => [0000|0000|0000|aaaa]
        __m128i s0 = __lsx_vsrli_h(utf16_packed, 12);
        // s1: [aaaa|bbbb|bbcc|cccc] => [0000|bbbb|bb00|0000]
        __m128i s1 = __lsx_vslli_h(utf16_packed, 2);
        // [0000|bbbb|bb00|0000] => [00bb|bbbb|0000|0000]
        s1 = __lsx_vand_v(s1, __lsx_vldi(-2753 /*0x3F00*/));
        // [00bb|bbbb|0000|aaaa]
        __m128i s2 = __lsx_vor_v(s0, s1);
        // s3: [00bb|bbbb|0000|aaaa] => [11bb|bbbb|1110|aaaa]
        __m128i v_c0e0 = __lsx_vreplgr2vr_h(uint16_t(0xC0E0));
        __m128i s3 = __lsx_vor_v(s2, v_c0e0);
        // __m128i v_07ff = vmovq_n_u16((uint16_t)0x07FF);
        __m128i one_or_two_bytes_bytemask = __lsx_vsle_hu(utf16_packed, v_07ff);
        __m128i m0 = __lsx_vandn_v(one_or_two_bytes_bytemask,
                                   __lsx_vldi(-2752 /*0x4000*/));
        __m128i s4 = __lsx_vxor_v(s3, m0);

        // 4. expand code units 16-bit => 32-bit
        __m128i out0 = __lsx_vilvl_h(s4, t2);
        __m128i out1 = __lsx_vilvh_h(s4, t2);

        // 5. compress 32-bit code units into 1, 2 or 3 bytes -- 2 x shuffle
        __m128i one_byte_bytemask =
            __lsx_vsle_hu(utf16_packed, __lsx_vrepli_h(0x7F));

        __m128i one_or_two_bytes_bytemask_u16_to_u32_low =
            __lsx_vilvl_h(one_or_two_bytes_bytemask, zero);
        __m128i one_or_two_bytes_bytemask_u16_to_u32_high =
            __lsx_vilvh_h(one_or_two_bytes_bytemask, zero);

        __m128i one_byte_bytemask_u16_to_u32_low =
            __lsx_vilvl_h(one_byte_bytemask, one_byte_bytemask);
        __m128i one_byte_bytemask_u16_to_u32_high =
            __lsx_vilvh_h(one_byte_bytemask, one_byte_bytemask);

        const uint32_t mask0 =
            __lsx_vpickve2gr_bu(__lsx_vmskltz_h(__lsx_vor_v(
                                    one_or_two_bytes_bytemask_u16_to_u32_low,
                                    one_byte_bytemask_u16_to_u32_low)),
                                0);
        const uint32_t mask1 =
            __lsx_vpickve2gr_bu(__lsx_vmskltz_h(__lsx_vor_v(
                                    one_or_two_bytes_bytemask_u16_to_u32_high,
                                    one_byte_bytemask_u16_to_u32_high)),
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
      }
      // At least one 32-bit word will produce a surrogate pair in UTF-16 <=>
      // will produce four UTF-8 bytes.
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
        uint32_t word = buf[k];
        if ((word & 0xFFFFFF80) == 0) {
          *utf8_output++ = char(word);
        } else if ((word & 0xFFFFF800) == 0) {
          *utf8_output++ = char((word >> 6) | 0b11000000);
          *utf8_output++ = char((word & 0b111111) | 0b10000000);
        } else if ((word & 0xFFFF0000) == 0) {
          if (word >= 0xD800 && word <= 0xDFFF) {
            return std::make_pair(
                result(error_code::SURROGATE, buf - start + k),
                reinterpret_cast<char *>(utf8_output));
          }
          *utf8_output++ = char((word >> 12) | 0b11100000);
          *utf8_output++ = char(((word >> 6) & 0b111111) | 0b10000000);
          *utf8_output++ = char((word & 0b111111) | 0b10000000);
        } else {
          if (word > 0x10FFFF) {
            return std::make_pair(
                result(error_code::TOO_LARGE, buf - start + k),
                reinterpret_cast<char *>(utf8_output));
          }
          *utf8_output++ = char((word >> 18) | 0b11110000);
          *utf8_output++ = char(((word >> 12) & 0b111111) | 0b10000000);
          *utf8_output++ = char(((word >> 6) & 0b111111) | 0b10000000);
          *utf8_output++ = char((word & 0b111111) | 0b10000000);
        }
      }
      buf += k;
    }
  } // while

  return std::make_pair(result(error_code::SUCCESS, buf - start),
                        reinterpret_cast<char *>(utf8_output));
}
