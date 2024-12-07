// Convert up to 16 bytes from utf8 to utf16 using a mask indicating the
// end of the code points. Only the least significant 12 bits of the mask
// are accessed.
// It returns how many bytes were consumed (up to 16, usually 12).
template <endianness big_endian>
size_t convert_masked_utf8_to_utf16(const char *input,
                                    uint64_t utf8_end_of_code_point_mask,
                                    char16_t *&utf16_output) {
  // we use an approach where we try to process up to 12 input bytes.
  // Why 12 input bytes and not 16? Because we are concerned with the size of
  // the lookup tables. Also 12 is nicely divisible by two and three.
  //
  __m128i in = __lsx_vld(reinterpret_cast<const uint8_t *>(input), 0);
  const uint16_t input_utf8_end_of_code_point_mask =
      utf8_end_of_code_point_mask & 0xfff;
  //
  // Optimization note: our main path below is load-latency dependent. Thus it
  // is maybe beneficial to have fast paths that depend on branch prediction but
  // have less latency. This results in more instructions but, potentially, also
  // higher speeds.

  // We first try a few fast paths.
  // The obvious first test is ASCII, which actually consumes the full 16.
  if ((utf8_end_of_code_point_mask & 0xFFFF) == 0xFFFF) {
    // We process in chunks of 16 bytes
    // The routine in simd.h is reused.
    simd8<int8_t> temp{in};
    temp.store_ascii_as_utf16<big_endian>(utf16_output);
    utf16_output += 16; // We wrote 16 16-bit characters.
    return 16;          // We consumed 16 bytes.
  }

  uint64_t buffer[2];
  // 3 byte sequences are the next most common, as seen in CJK, which has long
  // sequences of these.
  if (input_utf8_end_of_code_point_mask == 0x924) {
    // We want to take 4 3-byte UTF-8 code units and turn them into 4 2-byte
    // UTF-16 code units.
    __m128i composed = convert_utf8_3_byte_to_utf16(in);
    // Byte swap if necessary
    if (!match_system(big_endian)) {
      composed = lsx_swap_bytes(composed);
    }

    __lsx_vst(composed, reinterpret_cast<uint16_t *>(utf16_output), 0);
    utf16_output += 4; // We wrote 4 16-bit characters.
    return 12;         // We consumed 12 bytes.
  }

  // 2 byte sequences occur in short bursts in languages like Greek and Russian.
  if ((utf8_end_of_code_point_mask & 0xFFFF) == 0xAAAA) {
    // We want to take 6 2-byte UTF-8 code units and turn them into 6 2-byte
    // UTF-16 code units.
    __m128i composed = convert_utf8_2_byte_to_utf16(in);
    // Byte swap if necessary
    if (!match_system(big_endian)) {
      composed = lsx_swap_bytes(composed);
    }

    __lsx_vst(composed, reinterpret_cast<uint16_t *>(utf16_output), 0);
    utf16_output += 6; // We wrote 6 16-bit characters.
    return 12;         // We consumed 12 bytes.
  }

  /// We do not have a fast path available, or the fast path is unimportant, so
  /// we fallback.
  const uint8_t idx = simdutf::tables::utf8_to_utf16::utf8bigindex
      [input_utf8_end_of_code_point_mask][0];

  const uint8_t consumed = simdutf::tables::utf8_to_utf16::utf8bigindex
      [input_utf8_end_of_code_point_mask][1];
  const __m128i zero = __lsx_vldi(0);
  if (idx < 64) {
    // SIX (6) input code-code units
    // Convert to UTF-16
    __m128i composed = convert_utf8_1_to_2_byte_to_utf16(in, idx);
    // Byte swap if necessary
    if (!match_system(big_endian)) {
      composed = lsx_swap_bytes(composed);
    }
    // Store
    __lsx_vst(composed, reinterpret_cast<uint16_t *>(utf16_output), 0);
    utf16_output += 6; // We wrote 6 16-bit characters.
    return consumed;
  } else if (idx < 145) {
    // FOUR (4) input code-code units
    // UTF-16 and UTF-32 use similar algorithms, but UTF-32 skips the narrowing.
    __m128i sh = __lsx_vld(reinterpret_cast<const uint8_t *>(
                               simdutf::tables::utf8_to_utf16::shufutf8[idx]),
                           0);
    // XXX: depending on the system scalar instructions might be faster.
    // 1 byte: 00000000 00000000 0ccccccc
    // 2 byte: 00000000 110bbbbb 10cccccc
    // 3 byte: 1110aaaa 10bbbbbb 10cccccc
    sh = __lsx_vand_v(sh, __lsx_vldi(0x1f));
    __m128i perm = __lsx_vshuf_b(zero, in, sh);
    // 1 byte: 00000000 0ccccccc
    // 2 byte: xx0bbbbb x0cccccc
    // 3 byte: xxbbbbbb x0cccccc
    __m128i lowperm = __lsx_vpickev_h(perm, perm);
    // 1 byte: 00000000 00000000
    // 2 byte: 00000000 00000000
    // 3 byte: 00000000 1110aaaa
    __m128i highperm = __lsx_vpickod_h(perm, perm);
    // 3 byte: aaaa0000 00000000
    highperm = __lsx_vslli_h(highperm, 12);
    // ASCII
    // 1 byte: 00000000 0ccccccc
    // 2+byte: 00000000 00cccccc
    __m128i ascii = __lsx_vand_v(lowperm, __lsx_vrepli_h(0x7f));
    // 1 byte: 00000000 00000000
    // 2 byte: xx0bbbbb 00000000
    // 3 byte: xxbbbbbb 00000000
    __m128i middlebyte = __lsx_vand_v(lowperm, __lsx_vldi(-2561) /*0xFF00*/);
    // 1 byte: 00000000 0ccccccc
    // 2 byte: 0010bbbb bbcccccc
    // 3 byte: 0010bbbb bbcccccc
    __m128i composed = __lsx_vor_v(__lsx_vsrli_h(middlebyte, 2), ascii);

    __m128i v0fff = __lsx_vreplgr2vr_h(uint16_t(0xfff));
    // aaaabbbb bbcccccc
    composed = __lsx_vbitsel_v(highperm, composed, v0fff);

    if (!match_system(big_endian)) {
      composed = lsx_swap_bytes(composed);
    }

    __lsx_vst(composed, reinterpret_cast<uint16_t *>(utf16_output), 0);
    utf16_output += 4; // We wrote 4 16-bit codepoints
    return consumed;
  } else if (idx < 209) {
    // THREE (3) input code-code units
    if (input_utf8_end_of_code_point_mask == 0x888) {
      // We want to take 3 4-byte UTF-8 code units and turn them into 3 4-byte
      // UTF-16 pairs. Generating surrogate pairs is a little tricky though, but
      // it is easier when we can assume they are all pairs. This version does
      // not use the LUT, but 4 byte sequences are less common and the overhead
      // of the extra memory access is less important than the early branch
      // overhead in shorter sequences.

      // Swap byte pairs
      // 10dddddd 10cccccc|10bbbbbb 11110aaa
      // 10cccccc 10dddddd|11110aaa 10bbbbbb
      __m128i swap = lsx_swap_bytes(in);
      // Shift left 2 bits
      // cccccc00 dddddd00 xxxxxxxx bbbbbb00
      __m128i shift = __lsx_vslli_b(swap, 2);
      // Create a magic number containing the low 2 bits of the trail surrogate
      // and all the corrections needed to create the pair. UTF-8 4b prefix   =
      // -0x0000|0xF000 surrogate offset  = -0x0000|0x0040 (0x10000 << 6)
      // surrogate high    = +0x0000|0xD800
      // surrogate low     = +0xDC00|0x0000
      // -------------------------------
      //                   = +0xDC00|0xE7C0
      __m128i magic = __lsx_vreplgr2vr_w(uint32_t(0xDC00E7C0));
      // Generate unadjusted trail surrogate minus lowest 2 bits
      // vec(0000FF00) = __lsx_vldi(-1758)
      // xxxxxxxx xxxxxxxx|11110aaa bbbbbb00
      __m128i trail =
          __lsx_vbitsel_v(shift, swap, __lsx_vldi(-1758 /*0000FF00*/));
      // Insert low 2 bits of trail surrogate to magic number for later
      // 11011100 00000000 11100111 110000cc
      __m128i magic_with_low_2 = __lsx_vor_v(__lsx_vsrli_w(shift, 30), magic);

      // Generate lead surrogate
      // xxxxcccc ccdddddd|xxxxxxxx xxxxxxxx
      // 000000cc ccdddddd|xxxxxxxx xxxxxxxx
      __m128i lead = __lsx_vbitsel_v(
          __lsx_vsrli_h(__lsx_vand_v(shift, __lsx_vldi(0x3F)), 4), swap,
          __lsx_vrepli_h(0x3f /* 0x003f*/));

      // Blend pairs
      // __lsx_vldi(-1741) => vec(0x0000FFFF)
      // 000000cc ccdddddd|11110aaa bbbbbb00
      __m128i blend =
          __lsx_vbitsel_v(lead, trail, __lsx_vldi(-1741) /* (0x0000FFFF)*4 */);

      // Add magic number to finish the result
      // 110111CC CCDDDDDD|110110AA BBBBBBCC
      __m128i composed = __lsx_vadd_h(blend, magic_with_low_2);
      // Byte swap if necessary
      if (!match_system(big_endian)) {
        composed = lsx_swap_bytes(composed);
      }
      // __lsx_vst(composed, reinterpret_cast<uint16_t *>(utf16_output), 0);
      __lsx_vst(composed, reinterpret_cast<uint16_t *>(buffer), 0);
      std::memcpy(utf16_output, buffer, 12);
      utf16_output += 6; // We 3 32-bit surrogate pairs.
      return 12;         // We consumed 12 bytes.
    }
    // 3 1-4 byte sequences
    __m128i sh = __lsx_vld(reinterpret_cast<const uint8_t *>(
                               simdutf::tables::utf8_to_utf16::shufutf8[idx]),
                           0);
    // 1 byte: 00000000 00000000 00000000 0ddddddd
    // 3 byte: 00000000 00000000 110ccccc 10dddddd
    // 3 byte: 00000000 1110bbbb 10cccccc 10dddddd
    // 4 byte: 11110aaa 10bbbbbb 10cccccc 10dddddd
    sh = __lsx_vand_v(sh, __lsx_vldi(0x1f));
    __m128i perm = __lsx_vshuf_b(zero, in, sh);
    // added to fix issue https://github.com/simdutf/simdutf/issues/514
    // We only want to write 2 * 16-bit code units when that is actually what we
    // have. Unfortunately, we cannot trust the input. So it is possible to get
    // 0xff as an input byte and it should not result in a surrogate pair. We
    // need to check for that.
    uint32_t permbuffer[4];
    __lsx_vst(perm, permbuffer, 0);
    // Mask the low and middle bytes
    // 00000000 00000000 00000000 0ddddddd
    __m128i ascii = __lsx_vand_v(perm, __lsx_vrepli_w(0x7f));
    // Because the surrogates need more work, the high surrogate is computed
    // first.
    __m128i middlehigh = __lsx_vslli_w(perm, 2);
    // 00000000 00000000 00cccccc 00000000
    __m128i middlebyte = __lsx_vand_v(perm, __lsx_vldi(-3777) /* 0x00003F00 */);
    // Start assembling the sequence. Since the 4th byte is in the same position
    // as it would be in a surrogate and there is no dependency, shift left
    // instead of right. 3 byte: 00000000 10bbbbxx xxxxxxxx xxxxxxxx 4 byte:
    // 11110aaa bbbbbbxx xxxxxxxx xxxxxxxx
    __m128i ab =
        __lsx_vbitsel_v(middlehigh, perm, __lsx_vldi(-1656) /*0xFF000000*/);
    // Top 16 bits contains the high ten bits of the surrogate pair before
    // correction 3 byte: 00000000 10bbbbcc|cccc0000 00000000 4 byte: 11110aaa
    // bbbbbbcc|cccc0000 00000000 - high 10 bits correct w/o correction
    __m128i v_fffc0000 = __lsx_vreplgr2vr_w(uint32_t(0xFFFC0000));
    __m128i abc = __lsx_vbitsel_v(__lsx_vslli_w(middlebyte, 4), ab, v_fffc0000);
    // Combine the low 6 or 7 bits by a shift right accumulate
    // 3 byte: 00000000 00000010|bbbbcccc ccdddddd - low 16 bits correct
    // 4 byte: 00000011 110aaabb|bbbbcccc ccdddddd - low 10 bits correct w/o
    // correction
    __m128i composed = __lsx_vor_v(ascii, __lsx_vsrli_w(abc, 6));
    // After this is for surrogates
    // Blend the low and high surrogates
    // 4 byte: 11110aaa bbbbbbcc|bbbbcccc ccdddddd
    __m128i mixed =
        __lsx_vbitsel_v(abc, composed, __lsx_vldi(-1741) /*0x0000FFFF*/);
    // Clear the upper 6 bits of the low surrogate. Don't clear the upper bits
    // yet as 0x10000 was not subtracted from the codepoint yet. 4 byte:
    // 11110aaa bbbbbbcc|000000cc ccdddddd
    __m128i v_ffff03ff = __lsx_vreplgr2vr_w(uint32_t(0xFFFF03FF));
    __m128i masked_pair = __lsx_vand_v(mixed, v_ffff03ff);
    // Correct the remaining UTF-8 prefix, surrogate offset, and add the
    // surrogate prefixes in one magic 16-bit addition. similar magic number but
    // without the continue byte adjust and halfword swapped UTF-8 4b prefix   =
    // -0xF000|0x0000 surrogate offset  = -0x0040|0x0000 (0x10000 << 6)
    // surrogate high    = +0xD800|0x0000
    // surrogate low     = +0x0000|0xDC00
    // -----------------------------------
    //                   = +0xE7C0|0xDC00
    __m128i magic = __lsx_vreplgr2vr_w(uint32_t(0xE7C0DC00));
    // 4 byte: 110110AA BBBBBBCC|110111CC CCDDDDDD - surrogate pair complete
    __m128i surrogates = __lsx_vadd_w(masked_pair, magic);
    // If the high bit is 1 (s32 less than zero), this needs a surrogate pair
    __m128i is_pair = __lsx_vslt_w(perm, zero);
    // Select either the 4 byte surrogate pair or the 2 byte solo codepoint
    // 3 byte: 0xxxxxxx xxxxxxxx|bbbbcccc ccdddddd
    // 4 byte: 110110AA BBBBBBCC|110111CC CCDDDDDD
    __m128i selected = __lsx_vbitsel_v(composed, surrogates, is_pair);
    // Byte swap if necessary
    if (!match_system(big_endian)) {
      selected = lsx_swap_bytes(selected);
    }
    // Attempting to shuffle and store would be complex, just scalarize.
    uint32_t buffer_tmp[4];
    __lsx_vst(selected, buffer_tmp, 0);
    // Test for the top bit of the surrogate mask. Remove due to issue 514
    // const uint32_t SURROGATE_MASK = match_system(big_endian) ? 0x80000000 :
    // 0x00800000;
    for (size_t i = 0; i < 3; i++) {
      // Surrogate
      // Used to be if (buffer[i] & SURROGATE_MASK) {
      // See discussion above.
      // patch for issue https://github.com/simdutf/simdutf/issues/514
      if ((permbuffer[i] & 0xf8000000) == 0xf0000000) {
        utf16_output[0] = uint16_t(buffer_tmp[i] >> 16);
        utf16_output[1] = uint16_t(buffer_tmp[i] & 0xFFFF);
        utf16_output += 2;
      } else {
        utf16_output[0] = uint16_t(buffer_tmp[i] & 0xFFFF);
        utf16_output++;
      }
    }
    return consumed;
  } else {
    // here we know that there is an error but we do not handle errors
    return 12;
  }
}
