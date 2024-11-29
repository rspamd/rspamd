// Convert up to 12 bytes from utf8 to utf32 using a mask indicating the
// end of the code points. Only the least significant 12 bits of the mask
// are accessed.
// It returns how many bytes were consumed (up to 12).
size_t convert_masked_utf8_to_utf32(const char *input,
                                    uint64_t utf8_end_of_code_point_mask,
                                    char32_t *&utf32_out) {
  // we use an approach where we try to process up to 12 input bytes.
  // Why 12 input bytes and not 16? Because we are concerned with the size of
  // the lookup tables. Also 12 is nicely divisible by two and three.
  //
  uint32_t *&utf32_output = reinterpret_cast<uint32_t *&>(utf32_out);
  __m128i in = __lsx_vld(reinterpret_cast<const uint8_t *>(input), 0);
  const uint16_t input_utf8_end_of_code_point_mask =
      utf8_end_of_code_point_mask & 0xFFF;
  //
  // Optimization note: our main path below is load-latency dependent. Thus it
  // is maybe beneficial to have fast paths that depend on branch prediction but
  // have less latency. This results in more instructions but, potentially, also
  // higher speeds.
  //
  // We first try a few fast paths.
  if ((utf8_end_of_code_point_mask & 0xffff) == 0xffff) {
    // We process in chunks of 16 bytes.
    // use fast implementation in src/simdutf/arm64/simd.h
    // Ideally the compiler can keep the tables in registers.
    simd8<int8_t> temp{in};
    temp.store_ascii_as_utf32_tbl(utf32_out);
    utf32_output += 16; // We wrote 16 32-bit characters.
    return 16;          // We consumed 16 bytes.
  }
  __m128i zero = __lsx_vldi(0);
  if (input_utf8_end_of_code_point_mask == 0x924) {
    // We want to take 4 3-byte UTF-8 code units and turn them into 4 4-byte
    // UTF-32 code units. Convert to UTF-16
    __m128i composed_utf16 = convert_utf8_3_byte_to_utf16(in);
    __m128i utf32_low = __lsx_vilvl_h(zero, composed_utf16);

    __lsx_vst(utf32_low, reinterpret_cast<uint32_t *>(utf32_output), 0);
    utf32_output += 4; // We wrote 4 32-bit characters.
    return 12;         // We consumed 12 bytes.
  }
  // 2 byte sequences occur in short bursts in languages like Greek and Russian.
  if (input_utf8_end_of_code_point_mask == 0xaaa) {
    // We want to take 6 2-byte UTF-8 code units and turn them into 6 4-byte
    // UTF-32 code units. Convert to UTF-16
    __m128i composed_utf16 = convert_utf8_2_byte_to_utf16(in);

    __m128i utf32_low = __lsx_vilvl_h(zero, composed_utf16);
    __m128i utf32_high = __lsx_vilvh_h(zero, composed_utf16);

    __lsx_vst(utf32_low, reinterpret_cast<uint32_t *>(utf32_output), 0);
    __lsx_vst(utf32_high, reinterpret_cast<uint32_t *>(utf32_output), 16);
    utf32_output += 6;
    return 12; // We consumed 12 bytes.
  }
  /// Either no fast path or an unimportant fast path.

  const uint8_t idx = simdutf::tables::utf8_to_utf16::utf8bigindex
      [input_utf8_end_of_code_point_mask][0];
  const uint8_t consumed = simdutf::tables::utf8_to_utf16::utf8bigindex
      [input_utf8_end_of_code_point_mask][1];

  if (idx < 64) {
    // SIX (6) input code-code units
    // Convert to UTF-16
    __m128i composed_utf16 = convert_utf8_1_to_2_byte_to_utf16(in, idx);
    __m128i utf32_low = __lsx_vilvl_h(zero, composed_utf16);
    __m128i utf32_high = __lsx_vilvh_h(zero, composed_utf16);

    __lsx_vst(utf32_low, reinterpret_cast<uint32_t *>(utf32_output), 0);
    __lsx_vst(utf32_high, reinterpret_cast<uint32_t *>(utf32_output), 16);
    utf32_output += 6;
    return consumed;
  } else if (idx < 145) {
    // FOUR (4) input code-code units
    // UTF-16 and UTF-32 use similar algorithms, but UTF-32 skips the narrowing.
    __m128i sh = __lsx_vld(reinterpret_cast<const uint8_t *>(
                               simdutf::tables::utf8_to_utf16::shufutf8[idx]),
                           0);
    // Shuffle
    // 1 byte: 00000000 00000000 0ccccccc
    // 2 byte: 00000000 110bbbbb 10cccccc
    // 3 byte: 1110aaaa 10bbbbbb 10cccccc
    sh = __lsx_vand_v(sh, __lsx_vldi(0x1f));
    __m128i perm = __lsx_vshuf_b(zero, in, sh);
    // Split
    // 00000000 00000000 0ccccccc
    __m128i ascii = __lsx_vand_v(perm, __lsx_vrepli_w(0x7F)); // 6 or 7 bits
    // Note: unmasked
    // xxxxxxxx aaaaxxxx xxxxxxxx
    __m128i high =
        __lsx_vsrli_w(__lsx_vand_v(perm, __lsx_vldi(0xf)), 4); // 4 bits
    // Use 16 bit bic instead of and.
    // The top bits will be corrected later in the bsl
    // 00000000 10bbbbbb 00000000
    __m128i middle =
        __lsx_vand_v(perm, __lsx_vldi(-1758 /*0x0000FF00*/)); // 5 or 6 bits
    // Combine low and middle with shift right accumulate
    // 00000000 00xxbbbb bbcccccc
    __m128i lowmid = __lsx_vor_v(ascii, __lsx_vsrli_w(middle, 2));
    // Insert top 4 bits from high byte with bitwise select
    // 00000000 aaaabbbb bbcccccc
    __m128i composed =
        __lsx_vbitsel_v(lowmid, high, __lsx_vldi(-3600 /*0x0000F000*/));
    __lsx_vst(composed, utf32_output, 0);
    utf32_output += 4; // We wrote 4 32-bit characters.
    return consumed;
  } else if (idx < 209) {
    // THREE (3) input code-code units
    if (input_utf8_end_of_code_point_mask == 0x888) {
      // We want to take 3 4-byte UTF-8 code units and turn them into 3 4-byte
      // UTF-32 code units. This uses the same method as the fixed 3 byte
      // version, reversing and shift left insert. However, there is no need for
      // a shuffle mask now, just rev16 and rev32.
      //
      // This version does not use the LUT, but 4 byte sequences are less common
      // and the overhead of the extra memory access is less important than the
      // early branch overhead in shorter sequences, so it comes last.

      // Swap pairs of bytes
      // 10dddddd|10cccccc|10bbbbbb|11110aaa
      // 10cccccc 10dddddd|11110aaa 10bbbbbb
      __m128i swap = lsx_swap_bytes(in);
      // Shift left and insert
      // xxxxcccc ccdddddd|xxxxxxxa aabbbbbb
      __m128i merge1 = __lsx_vbitsel_v(__lsx_vsrli_h(swap, 2), swap,
                                       __lsx_vrepli_h(0x3f /*0x003F*/));
      // Shift insert again
      // xxxxxxxx xxxaaabb bbbbcccc ccdddddd
      __m128i merge2 =
          __lsx_vbitsel_v(__lsx_vslli_w(merge1, 12), /* merge1 << 12 */
                          __lsx_vsrli_w(merge1, 16), /* merge1 >> 16 */
                          __lsx_vldi(-2545));        /*0x00000FFF*/
      // Clear the garbage
      // 00000000 000aaabb bbbbcccc ccdddddd
      __m128i composed = __lsx_vand_v(merge2, __lsx_vldi(-2273 /*0x1FFFFF*/));
      // Store
      __lsx_vst(composed, utf32_output, 0);
      utf32_output += 3; // We wrote 3 32-bit characters.
      return 12;         // We consumed 12 bytes.
    }
    // Unlike UTF-16, doing a fast codepath doesn't have nearly as much benefit
    // due to surrogates no longer being involved.
    __m128i sh = __lsx_vld(reinterpret_cast<const uint8_t *>(
                               simdutf::tables::utf8_to_utf16::shufutf8[idx]),
                           0);
    // 1 byte: 00000000 00000000 00000000 0ddddddd
    // 2 byte: 00000000 00000000 110ccccc 10dddddd
    // 3 byte: 00000000 1110bbbb 10cccccc 10dddddd
    // 4 byte: 11110aaa 10bbbbbb 10cccccc 10dddddd
    sh = __lsx_vand_v(sh, __lsx_vldi(0x1f));
    __m128i perm = __lsx_vshuf_b(zero, in, sh);

    // Ascii
    __m128i ascii = __lsx_vand_v(perm, __lsx_vrepli_w(0x7F));
    __m128i middle = __lsx_vand_v(perm, __lsx_vldi(-3777 /*0x00003f00*/));
    // 00000000 00000000 0000cccc ccdddddd
    __m128i cd =
        __lsx_vbitsel_v(__lsx_vsrli_w(middle, 2), ascii, __lsx_vrepli_w(0x3f));

    __m128i correction = __lsx_vand_v(perm, __lsx_vldi(-3520 /*0x00400000*/));
    __m128i corrected = __lsx_vadd_b(perm, __lsx_vsrli_w(correction, 1));
    // Insert twice
    // 00000000 000aaabb bbbbxxxx xxxxxxxx
    __m128i corrected_srli2 =
        __lsx_vsrli_w(__lsx_vand_v(corrected, __lsx_vrepli_b(0x7)), 2);
    __m128i ab =
        __lsx_vbitsel_v(corrected_srli2, corrected, __lsx_vrepli_h(0x3f));
    ab = __lsx_vsrli_w(ab, 4);
    // 00000000 000aaabb bbbbcccc ccdddddd
    __m128i composed =
        __lsx_vbitsel_v(ab, cd, __lsx_vldi(-2545 /*0x00000FFF*/));
    // Store
    __lsx_vst(composed, utf32_output, 0);
    utf32_output += 3; // We wrote 3 32-bit characters.
    return consumed;
  } else {
    // here we know that there is an error but we do not handle errors
    return 12;
  }
}
